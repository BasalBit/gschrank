#![forbid(unsafe_code)]

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use crate::{MAX_ENVELOPE_SIZE, profiles::BackupDestinationError};

use super::system;

const TEMP_ATTEMPTS: usize = 16;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Restrictive, create-only persistence for one user-selected encrypted backup.
pub(crate) struct EncryptedBackupWriter {
    destination: PathBuf,
}

impl EncryptedBackupWriter {
    pub(crate) fn new(destination: PathBuf) -> Self {
        Self { destination }
    }

    pub(crate) fn create(&self, envelope: &[u8]) -> Result<(), BackupDestinationError> {
        self.create_with_after_publish(envelope, || Ok(()))
    }

    fn create_with_after_publish(
        &self,
        envelope: &[u8],
        after_publish: impl FnOnce() -> Result<(), ()>,
    ) -> Result<(), BackupDestinationError> {
        if envelope.len() > MAX_ENVELOPE_SIZE {
            return Err(BackupDestinationError::IoFailure);
        }
        let parent = validate_destination(&self.destination)?;
        let mut temporary = TemporaryBackup::create(parent, envelope)?;

        match fs::hard_link(temporary.path(), &self.destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(classify_existing(&self.destination));
            }
            Err(error) => return Err(map_io(error)),
        }

        // From this point the final name may exist. Any later error must not
        // imply that retrying at the same path is safe.
        if after_publish().is_err() {
            return Err(BackupDestinationError::OutcomeIndeterminate);
        }
        if sync_directory(parent).is_err() {
            return Err(BackupDestinationError::OutcomeIndeterminate);
        }
        if temporary.remove().is_err() || sync_directory(parent).is_err() {
            return Err(BackupDestinationError::OutcomeIndeterminate);
        }
        if verify_committed(&self.destination, envelope).is_err() {
            return Err(BackupDestinationError::OutcomeIndeterminate);
        }
        Ok(())
    }
}

fn validate_destination(destination: &Path) -> Result<&Path, BackupDestinationError> {
    if !destination.is_absolute() || destination.file_name().is_none() {
        return Err(BackupDestinationError::UnsafePath);
    }
    for component in destination.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(BackupDestinationError::UnsafePath);
        }
    }
    let parent = destination
        .parent()
        .ok_or(BackupDestinationError::UnsafePath)?;
    validate_directory_chain(parent)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(map_io)?;
    if parent_metadata.uid() != system::effective_user_id() {
        return Err(BackupDestinationError::UnsafePath);
    }
    if !system::is_apfs(parent).map_err(map_io)? {
        return Err(BackupDestinationError::UnsupportedStorage);
    }
    match fs::symlink_metadata(destination) {
        Ok(_) => Err(classify_existing(destination)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(parent),
        Err(error) => Err(map_io(error)),
    }
}

fn validate_directory_chain(directory: &Path) -> Result<(), BackupDestinationError> {
    let mut current = PathBuf::new();
    for component in directory.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(map_io)?;
        if !metadata.file_type().is_dir() {
            return Err(BackupDestinationError::UnsafePath);
        }
    }
    Ok(())
}

fn classify_existing(destination: &Path) -> BackupDestinationError {
    let Ok(metadata) = fs::symlink_metadata(destination) else {
        return BackupDestinationError::AlreadyExists;
    };
    if metadata.file_type().is_file()
        && metadata.uid() == system::effective_user_id()
        && metadata.permissions().mode() & 0o777 == 0o600
    {
        BackupDestinationError::AlreadyExists
    } else {
        BackupDestinationError::UnsafePath
    }
}

fn verify_committed(destination: &Path, expected: &[u8]) -> Result<(), BackupDestinationError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(destination).map_err(map_io)?;
    validate_backup_file(&file.metadata().map_err(map_io)?)?;
    let mut bytes = Vec::with_capacity(expected.len());
    file.take((MAX_ENVELOPE_SIZE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes != expected {
        return Err(BackupDestinationError::IoFailure);
    }
    Ok(())
}

fn validate_backup_file(metadata: &Metadata) -> Result<(), BackupDestinationError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != system::effective_user_id()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        Err(BackupDestinationError::UnsafePath)
    } else {
        Ok(())
    }
}

struct TemporaryBackup {
    path: Option<PathBuf>,
}

impl TemporaryBackup {
    fn create(parent: &Path, envelope: &[u8]) -> Result<Self, BackupDestinationError> {
        for _ in 0..TEMP_ATTEMPTS {
            let path = parent.join(temporary_name()?);
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            let mut file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(map_io(error)),
            };
            let result = (|| {
                validate_backup_file(&file.metadata().map_err(map_io)?)?;
                file.write_all(envelope).map_err(map_io)?;
                file.flush().map_err(map_io)?;
                system::full_sync(&file).map_err(map_io)
            })();
            if let Err(error) = result {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
            return Ok(Self { path: Some(path) });
        }
        Err(BackupDestinationError::IoFailure)
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("temporary backup path")
    }

    fn remove(&mut self) -> io::Result<()> {
        let path = self.path.as_deref().expect("temporary backup path");
        fs::remove_file(path)?;
        self.path = None;
        Ok(())
    }
}

impl Drop for TemporaryBackup {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn temporary_name() -> Result<String, BackupDestinationError> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| BackupDestinationError::IoFailure)?;
    let mut name = String::from(".gschrank-backup-");
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(".tmp");
    Ok(name)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn map_io(error: io::Error) -> BackupDestinationError {
    let kind = error.kind();
    let native = error.raw_os_error();
    drop(error);
    match (kind, native) {
        (_, Some(libc::ELOOP)) => BackupDestinationError::UnsafePath,
        (io::ErrorKind::PermissionDenied, _) => BackupDestinationError::PermissionDenied,
        (io::ErrorKind::AlreadyExists, _) => BackupDestinationError::AlreadyExists,
        _ => BackupDestinationError::IoFailure,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{DirBuilderExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{
        EnvironmentName, ProfileName, SecretValue,
        init::Initializer,
        key_provider::{InteractionPolicy, KeyProviderErrorKind},
        platform::macos::LocalVaultStore,
        profiles::{BackupOperationError, ProfileOperationError, ProfileOperations},
        testing::MemoryKeyProvider,
        vault_store::{VaultStore, VaultStoreError},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("gschrank-backup-test-{}-{id}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(&root).unwrap();
            Self(root)
        }

        fn destination(&self) -> PathBuf {
            self.0.join("vault.backup")
        }

        fn data(&self) -> PathBuf {
            self.0.join("data")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_an_exact_restrictive_backup_without_leaving_a_temporary() {
        let test = TestDirectory::new();
        let destination = test.destination();
        let envelope = b"authenticated-encrypted-envelope";

        EncryptedBackupWriter::new(destination.clone())
            .create(envelope)
            .unwrap();

        assert_eq!(fs::read(&destination).unwrap(), envelope);
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().uid(),
            system::effective_user_id()
        );
        assert_eq!(fs::read_dir(&test.0).unwrap().count(), 1);
    }

    #[test]
    fn refuses_relative_existing_and_symlinked_destinations_without_replacement() {
        assert_eq!(
            EncryptedBackupWriter::new(PathBuf::from("relative.backup"))
                .create(b"encrypted")
                .unwrap_err(),
            BackupDestinationError::UnsafePath
        );

        let existing = TestDirectory::new();
        let destination = existing.destination();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
            .open(&destination)
            .unwrap()
            .write_all(b"keep")
            .unwrap();
        assert_eq!(
            EncryptedBackupWriter::new(destination.clone())
                .create(b"replacement")
                .unwrap_err(),
            BackupDestinationError::AlreadyExists
        );
        assert_eq!(fs::read(destination).unwrap(), b"keep");

        let linked = TestDirectory::new();
        let outside = linked.0.join("outside");
        fs::write(&outside, b"keep outside").unwrap();
        symlink(&outside, linked.destination()).unwrap();
        assert_eq!(
            EncryptedBackupWriter::new(linked.destination())
                .create(b"replacement")
                .unwrap_err(),
            BackupDestinationError::UnsafePath
        );
        assert_eq!(fs::read(outside).unwrap(), b"keep outside");

        let parent_link = TestDirectory::new();
        let real = parent_link.0.join("real");
        fs::create_dir(&real).unwrap();
        let alias = parent_link.0.join("alias");
        symlink(&real, &alias).unwrap();
        assert_eq!(
            EncryptedBackupWriter::new(alias.join("vault.backup"))
                .create(b"encrypted")
                .unwrap_err(),
            BackupDestinationError::UnsafePath
        );
        assert!(!real.join("vault.backup").exists());
    }

    #[test]
    fn authenticated_backup_copies_only_ciphertext_and_key_failure_writes_nothing() {
        let test = TestDirectory::new();
        let keys = MemoryKeyProvider::new();
        let store = LocalVaultStore::new(test.data());
        Initializer::new(&keys, &store)
            .initialize(InteractionPolicy::FailFast)
            .unwrap();
        let operations = ProfileOperations::new(&keys, &store);
        let profile = ProfileName::new("dev").unwrap();
        operations
            .create(profile.clone(), InteractionPolicy::FailFast)
            .unwrap();
        operations
            .set(
                &profile,
                EnvironmentName::new("TOKEN").unwrap(),
                SecretValue::from_string("CANARY-backup-$()`".to_owned()).unwrap(),
                InteractionPolicy::FailFast,
            )
            .unwrap();
        let live = store
            .shared_read::<_, VaultStoreError, _>(|read| {
                read.read_live()?.ok_or_else(|| {
                    VaultStoreError::new(crate::vault_store::VaultStoreErrorKind::MissingState)
                })
            })
            .unwrap();

        let destination = test.destination();
        let writer = EncryptedBackupWriter::new(destination.clone());
        let receipt = operations
            .backup_to(InteractionPolicy::FailFast, |envelope| {
                writer.create(envelope)
            })
            .unwrap();
        assert_eq!(receipt.revision, 2);
        let backup = fs::read(&destination).unwrap();
        assert_eq!(backup, live.as_slice());
        assert!(!backup.windows(6).any(|window| window == b"CANARY"));

        let refused = test.0.join("refused.backup");
        keys.fail_next_load(KeyProviderErrorKind::InteractionRequired);
        let error = operations
            .backup_to(InteractionPolicy::FailFast, |envelope| {
                EncryptedBackupWriter::new(refused.clone()).create(envelope)
            })
            .unwrap_err();
        assert!(matches!(
            error,
            BackupOperationError::Profile(ProfileOperationError::SecureStore(_))
        ));
        assert!(!refused.exists());
    }

    #[test]
    fn failure_after_atomic_publish_reports_an_indeterminate_existing_backup() {
        let test = TestDirectory::new();
        let destination = test.destination();
        let error = EncryptedBackupWriter::new(destination.clone())
            .create_with_after_publish(b"authenticated-encrypted-envelope", || Err(()))
            .unwrap_err();

        assert_eq!(error, BackupDestinationError::OutcomeIndeterminate);
        assert_eq!(error.exit_code(), 15);
        assert_eq!(
            fs::read(&destination).unwrap(),
            b"authenticated-encrypted-envelope"
        );
        assert_eq!(fs::read_dir(&test.0).unwrap().count(), 1);
        assert_eq!(
            EncryptedBackupWriter::new(destination)
                .create(b"replacement")
                .unwrap_err(),
            BackupDestinationError::AlreadyExists
        );
    }
}
