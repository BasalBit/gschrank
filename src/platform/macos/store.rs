#![forbid(unsafe_code)]

use std::{
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use zeroize::Zeroizing;

use crate::{
    MAX_ENVELOPE_SIZE,
    vault_store::{
        CommitOutcome, RecoveryArtifacts, RecoveryBundle, RecoveryBundleId, RecoveryBundleMetadata,
        RecoveryReason, VaultRead, VaultStore, VaultStoreError, VaultStoreErrorKind,
        VaultTransaction,
    },
};

use super::system;

const LIVE_FILE: &str = "vault";
const LOCK_FILE: &str = "vault.lock";
const INIT_PENDING_FILE: &str = "vault.init.pending";
const RECOVERY_DIRECTORY: &str = "recovery";
const RECOVERY_MANIFEST_FILE: &str = "manifest";
const RECOVERY_LIVE_FILE: &str = "vault";
const RECOVERY_INIT_FILE: &str = "vault.init.pending";
const RECOVERY_MANIFEST_MAGIC: &[u8; 8] = b"GSCHRCV1";
const RECOVERY_MANIFEST_VERSION: u16 = 1;
const RECOVERY_MANIFEST_LENGTH: usize = 40;
const RECOVERY_FLAG_LIVE: u8 = 0b0000_0001;
const RECOVERY_FLAG_INIT: u8 = 0b0000_0010;
const TEMP_ATTEMPTS: usize = 16;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy)]
enum DestinationState {
    Absent,
    Present,
}

/// Locked, permission-validating local encrypted-vault storage for macOS/APFS.
pub(crate) struct LocalVaultStore {
    directory: PathBuf,
}

impl LocalVaultStore {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn prepare_directory(&self, create: bool) -> Result<(), VaultStoreError> {
        let mut created = false;
        match fs::symlink_metadata(&self.directory) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(&self.directory).map_err(map_directory_io)?;
                created = true;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(VaultStoreError::new(VaultStoreErrorKind::MissingState));
            }
            Err(error) => return Err(map_directory_io(error)),
        }

        let metadata = fs::symlink_metadata(&self.directory).map_err(map_directory_io)?;
        validate_directory(&metadata)?;
        if !system::is_apfs(&self.directory).map_err(map_directory_io)? {
            return Err(VaultStoreError::new(
                VaultStoreErrorKind::UnsupportedStorage,
            ));
        }
        if created {
            let parent = self
                .directory
                .parent()
                .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::UnsafePath))?;
            sync_directory(parent)
                .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::OutcomeIndeterminate))?;
        }
        Ok(())
    }

    fn open_lock(&self, create: bool) -> Result<File, VaultStoreError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(create)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let lock = match options.open(self.directory.join(LOCK_FILE)) {
            Ok(lock) => lock,
            Err(error) if !create && error.kind() == io::ErrorKind::NotFound => {
                return Err(VaultStoreError::new(VaultStoreErrorKind::MissingState));
            }
            Err(error) => return Err(map_file_io(error)),
        };
        validate_regular_file(&lock.metadata().map_err(map_file_io)?)?;
        Ok(lock)
    }
}

impl VaultStore for LocalVaultStore {
    fn initialization_transaction<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<VaultStoreError>,
        F: FnOnce(&mut dyn VaultTransaction) -> Result<T, E>,
    {
        self.prepare_directory(true).map_err(E::from)?;
        let lock = self.open_lock(true).map_err(E::from)?;
        lock.lock().map_err(|error| E::from(map_lock_io(error)))?;
        let mut transaction = LocalTransaction {
            directory: &self.directory,
            _lock: lock,
        };
        operation(&mut transaction)
    }

    fn shared_read<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<VaultStoreError>,
        F: FnOnce(&mut dyn VaultRead) -> Result<T, E>,
    {
        self.prepare_directory(false).map_err(E::from)?;
        let lock = self.open_lock(false).map_err(E::from)?;
        lock.lock_shared()
            .map_err(|error| E::from(map_lock_io(error)))?;
        let mut transaction = LocalTransaction {
            directory: &self.directory,
            _lock: lock,
        };
        operation(&mut transaction)
    }

    fn exclusive_transaction<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<VaultStoreError>,
        F: FnOnce(&mut dyn VaultTransaction) -> Result<T, E>,
    {
        self.prepare_directory(false).map_err(E::from)?;
        let lock = self.open_lock(false).map_err(E::from)?;
        lock.lock().map_err(|error| E::from(map_lock_io(error)))?;
        let mut transaction = LocalTransaction {
            directory: &self.directory,
            _lock: lock,
        };
        operation(&mut transaction)
    }
}

struct LocalTransaction<'directory> {
    directory: &'directory Path,
    _lock: File,
}

impl VaultRead for LocalTransaction<'_> {
    fn read_live(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError> {
        read_artifact(self.directory, LIVE_FILE)
    }

    fn read_init_pending(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError> {
        read_artifact(self.directory, INIT_PENDING_FILE)
    }

    fn read_recovery_bundles(&mut self) -> Result<Vec<RecoveryBundle>, VaultStoreError> {
        read_recovery_bundles(self.directory)
    }
}

impl VaultTransaction for LocalTransaction<'_> {
    fn create_init_pending(&mut self, envelope: &[u8]) -> Result<(), VaultStoreError> {
        if artifact_exists(self.directory, LIVE_FILE)?
            || artifact_exists(self.directory, INIT_PENDING_FILE)?
        {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        durably_install(
            self.directory,
            INIT_PENDING_FILE,
            envelope,
            DestinationState::Absent,
        )
        .map(|_| ())
    }

    fn discard_init_pending(&mut self) -> Result<(), VaultStoreError> {
        if read_artifact(self.directory, INIT_PENDING_FILE)?.is_none() {
            return Ok(());
        }
        fs::remove_file(self.directory.join(INIT_PENDING_FILE)).map_err(map_file_io)?;
        sync_directory(self.directory)
            .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::OutcomeIndeterminate))
    }

    fn promote_init_pending(&mut self) -> Result<CommitOutcome, VaultStoreError> {
        if artifact_exists(self.directory, LIVE_FILE)? {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        let pending = read_artifact(self.directory, INIT_PENDING_FILE)?
            .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))?;
        match fs::rename(
            self.directory.join(INIT_PENDING_FILE),
            self.directory.join(LIVE_FILE),
        ) {
            Ok(()) => {
                sync_directory(self.directory)
                    .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::OutcomeIndeterminate))?;
                verify_artifact(self.directory, LIVE_FILE, &pending)
                    .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::OutcomeIndeterminate))?;
                Ok(CommitOutcome::Committed)
            }
            Err(error) => Err(map_file_io(error)),
        }
    }

    fn replace_live(&mut self, envelope: &[u8]) -> Result<CommitOutcome, VaultStoreError> {
        durably_install(
            self.directory,
            LIVE_FILE,
            envelope,
            DestinationState::Present,
        )
    }

    fn preserve_recovery(
        &mut self,
        metadata: RecoveryBundleMetadata,
        artifacts: RecoveryArtifacts<'_>,
    ) -> Result<CommitOutcome, VaultStoreError> {
        preserve_recovery_bundle(self.directory, metadata, artifacts)
    }
}

fn read_artifact(
    directory: &Path,
    name: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = match options.open(directory.join(name)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_file_io(error)),
    };
    let metadata = file.metadata().map_err(map_file_io)?;
    validate_regular_file(&metadata)?;
    if metadata.len() > MAX_ENVELOPE_SIZE as u64 {
        return Err(VaultStoreError::new(VaultStoreErrorKind::IoFailure));
    }

    let capacity = usize::try_from(metadata.len())
        .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::IoFailure))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take((MAX_ENVELOPE_SIZE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_file_io)?;
    if bytes.len() > MAX_ENVELOPE_SIZE {
        return Err(VaultStoreError::new(VaultStoreErrorKind::IoFailure));
    }
    Ok(Some(bytes))
}

fn artifact_exists(directory: &Path, name: &str) -> Result<bool, VaultStoreError> {
    match fs::symlink_metadata(directory.join(name)) {
        Ok(metadata) => {
            validate_regular_file(&metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(map_file_io(error)),
    }
}

fn durably_install(
    directory: &Path,
    destination: &str,
    envelope: &[u8],
    destination_state: DestinationState,
) -> Result<CommitOutcome, VaultStoreError> {
    if envelope.len() > MAX_ENVELOPE_SIZE {
        return Err(VaultStoreError::new(VaultStoreErrorKind::IoFailure));
    }
    validate_destination_state(directory, destination, destination_state)?;

    for _ in 0..TEMP_ATTEMPTS {
        let temporary_name = temporary_name()?;
        let temporary_path = directory.join(&temporary_name);
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = match options.open(&temporary_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(map_file_io(error)),
        };

        let write_result = (|| {
            validate_regular_file(&file.metadata().map_err(map_file_io)?)?;
            file.write_all(envelope).map_err(map_file_io)?;
            file.flush().map_err(map_file_io)?;
            system::full_sync(&file).map_err(map_file_io)?;
            drop(file);
            validate_destination_state(directory, destination, destination_state)?;
            fs::rename(&temporary_path, directory.join(destination)).map_err(map_file_io)?;
            sync_directory(directory)
                .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::OutcomeIndeterminate))?;
            verify_artifact(directory, destination, envelope)
                .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::OutcomeIndeterminate))?;
            Ok(CommitOutcome::Committed)
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        return write_result;
    }

    Err(VaultStoreError::new(VaultStoreErrorKind::Conflict))
}

#[allow(dead_code)]
fn preserve_recovery_bundle(
    directory: &Path,
    metadata: RecoveryBundleMetadata,
    artifacts: RecoveryArtifacts<'_>,
) -> Result<CommitOutcome, VaultStoreError> {
    if artifacts.live.is_none() && artifacts.init_pending.is_none() {
        return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
    }
    for envelope in [artifacts.live, artifacts.init_pending]
        .into_iter()
        .flatten()
    {
        if envelope.len() > MAX_ENVELOPE_SIZE {
            return Err(VaultStoreError::new(VaultStoreErrorKind::IoFailure));
        }
    }

    let recovery = ensure_recovery_directory(directory)?;
    let _existing = read_recovery_bundles(directory)?;
    let bundle_name = metadata.id.to_hex();
    let destination = recovery.join(&bundle_name);
    match fs::symlink_metadata(&destination) {
        Ok(existing) => {
            validate_directory(&existing)?;
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(map_directory_io(error)),
    }

    let temporary = recovery.join(format!(".gschrank-recovery-{bundle_name}.pending"));
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(&temporary).map_err(map_directory_io)?;
    validate_directory(&fs::symlink_metadata(&temporary).map_err(map_directory_io)?)?;

    let prepare_result = (|| {
        if let Some(live) = artifacts.live {
            write_new_synced(&temporary, RECOVERY_LIVE_FILE, live)?;
        }
        if let Some(pending) = artifacts.init_pending {
            write_new_synced(&temporary, RECOVERY_INIT_FILE, pending)?;
        }
        let manifest = encode_recovery_manifest(metadata, artifacts);
        write_new_synced(&temporary, RECOVERY_MANIFEST_FILE, &manifest)?;
        sync_directory(&temporary).map_err(map_directory_io)
    })();
    if let Err(error) = prepare_result {
        cleanup_recovery_temporary(&temporary);
        return Err(error);
    }

    if let Err(error) = fs::rename(&temporary, &destination) {
        cleanup_recovery_temporary(&temporary);
        return Err(map_directory_io(error));
    }
    sync_directory(&recovery)
        .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::OutcomeIndeterminate))?;
    let committed = read_recovery_bundle(&destination, metadata.id)
        .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::OutcomeIndeterminate))?;
    if committed.metadata != metadata
        || committed.live.as_ref().map(|bytes| bytes.as_slice()) != artifacts.live
        || committed
            .init_pending
            .as_ref()
            .map(|bytes| bytes.as_slice())
            != artifacts.init_pending
    {
        return Err(VaultStoreError::new(
            VaultStoreErrorKind::OutcomeIndeterminate,
        ));
    }
    Ok(CommitOutcome::Committed)
}

#[allow(dead_code)]
fn ensure_recovery_directory(directory: &Path) -> Result<PathBuf, VaultStoreError> {
    let recovery = directory.join(RECOVERY_DIRECTORY);
    match fs::symlink_metadata(&recovery) {
        Ok(metadata) => validate_directory(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(&recovery).map_err(map_directory_io)?;
            validate_directory(&fs::symlink_metadata(&recovery).map_err(map_directory_io)?)?;
            sync_directory(directory).map_err(map_directory_io)?;
        }
        Err(error) => return Err(map_directory_io(error)),
    }
    Ok(recovery)
}

fn read_recovery_bundles(directory: &Path) -> Result<Vec<RecoveryBundle>, VaultStoreError> {
    let recovery = directory.join(RECOVERY_DIRECTORY);
    match fs::symlink_metadata(&recovery) {
        Ok(metadata) => validate_directory(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(map_directory_io(error)),
    }

    let mut bundles = Vec::new();
    for entry in fs::read_dir(&recovery).map_err(map_directory_io)? {
        let entry = entry.map_err(map_directory_io)?;
        let entry_metadata = fs::symlink_metadata(entry.path()).map_err(map_directory_io)?;
        validate_directory(&entry_metadata)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::Conflict))?;
        let id = parse_recovery_bundle_id(&name)?;
        bundles.push(read_recovery_bundle(&entry.path(), id)?);
    }
    bundles.sort_by_key(|bundle| (bundle.metadata.created_at_unix_seconds, bundle.metadata.id));
    Ok(bundles)
}

fn read_recovery_bundle(
    directory: &Path,
    expected_id: RecoveryBundleId,
) -> Result<RecoveryBundle, VaultStoreError> {
    validate_directory(&fs::symlink_metadata(directory).map_err(map_directory_io)?)?;
    let manifest = read_exact_file(directory, RECOVERY_MANIFEST_FILE, RECOVERY_MANIFEST_LENGTH)?;
    let (metadata, flags) = decode_recovery_manifest(&manifest)?;
    if metadata.id != expected_id {
        return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
    }

    let live = if flags & RECOVERY_FLAG_LIVE != 0 {
        Some(
            read_artifact(directory, RECOVERY_LIVE_FILE)?
                .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::Conflict))?,
        )
    } else {
        None
    };
    let init_pending = if flags & RECOVERY_FLAG_INIT != 0 {
        Some(
            read_artifact(directory, RECOVERY_INIT_FILE)?
                .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::Conflict))?,
        )
    } else {
        None
    };
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(map_directory_io)? {
        let entry = entry.map_err(map_directory_io)?;
        entries.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::Conflict))?,
        );
    }
    entries.sort();
    let mut expected = vec![RECOVERY_MANIFEST_FILE];
    if live.is_some() {
        expected.push(RECOVERY_LIVE_FILE);
    }
    if init_pending.is_some() {
        expected.push(RECOVERY_INIT_FILE);
    }
    expected.sort_unstable();
    if entries != expected {
        return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
    }
    Ok(RecoveryBundle {
        metadata,
        live,
        init_pending,
    })
}

#[allow(dead_code)]
fn encode_recovery_manifest(
    metadata: RecoveryBundleMetadata,
    artifacts: RecoveryArtifacts<'_>,
) -> [u8; RECOVERY_MANIFEST_LENGTH] {
    let mut bytes = [0_u8; RECOVERY_MANIFEST_LENGTH];
    bytes[..8].copy_from_slice(RECOVERY_MANIFEST_MAGIC);
    bytes[8..10].copy_from_slice(&RECOVERY_MANIFEST_VERSION.to_be_bytes());
    bytes[10] = match metadata.reason {
        RecoveryReason::Restore => 1,
        RecoveryReason::Reset => 2,
        RecoveryReason::Rebuild => 3,
    };
    bytes[11] = (u8::from(artifacts.live.is_some()) * RECOVERY_FLAG_LIVE)
        | (u8::from(artifacts.init_pending.is_some()) * RECOVERY_FLAG_INIT);
    bytes[12..20].copy_from_slice(&metadata.created_at_unix_seconds.to_be_bytes());
    bytes[20..36].copy_from_slice(metadata.id.as_bytes());
    bytes
}

fn decode_recovery_manifest(bytes: &[u8]) -> Result<(RecoveryBundleMetadata, u8), VaultStoreError> {
    if bytes.len() != RECOVERY_MANIFEST_LENGTH
        || &bytes[..8] != RECOVERY_MANIFEST_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != RECOVERY_MANIFEST_VERSION
        || bytes[36..].iter().any(|byte| *byte != 0)
    {
        return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
    }
    let reason = match bytes[10] {
        1 => RecoveryReason::Restore,
        2 => RecoveryReason::Reset,
        3 => RecoveryReason::Rebuild,
        _ => return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict)),
    };
    let flags = bytes[11];
    if flags == 0 || flags & !(RECOVERY_FLAG_LIVE | RECOVERY_FLAG_INIT) != 0 {
        return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
    }
    let created_at_unix_seconds = u64::from_be_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::Conflict))?,
    );
    let id = RecoveryBundleId::from_bytes(
        bytes[20..36]
            .try_into()
            .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::Conflict))?,
    );
    Ok((
        RecoveryBundleMetadata {
            id,
            created_at_unix_seconds,
            reason,
        },
        flags,
    ))
}

fn parse_recovery_bundle_id(name: &str) -> Result<RecoveryBundleId, VaultStoreError> {
    RecoveryBundleId::from_hex(name)
        .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::Conflict))
}

#[allow(dead_code)]
fn write_new_synced(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), VaultStoreError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(directory.join(name)).map_err(map_file_io)?;
    validate_regular_file(&file.metadata().map_err(map_file_io)?)?;
    file.write_all(bytes).map_err(map_file_io)?;
    file.flush().map_err(map_file_io)?;
    system::full_sync(&file).map_err(map_file_io)
}

fn read_exact_file(
    directory: &Path,
    name: &str,
    expected_length: usize,
) -> Result<Vec<u8>, VaultStoreError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(directory.join(name)).map_err(map_file_io)?;
    let metadata = file.metadata().map_err(map_file_io)?;
    validate_regular_file(&metadata)?;
    if metadata.len() != expected_length as u64 {
        return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict));
    }
    let mut bytes = Vec::with_capacity(expected_length);
    file.read_to_end(&mut bytes).map_err(map_file_io)?;
    Ok(bytes)
}

#[allow(dead_code)]
fn cleanup_recovery_temporary(directory: &Path) {
    for name in [
        RECOVERY_MANIFEST_FILE,
        RECOVERY_LIVE_FILE,
        RECOVERY_INIT_FILE,
    ] {
        let _ = fs::remove_file(directory.join(name));
    }
    let _ = fs::remove_dir(directory);
}

fn verify_artifact(directory: &Path, name: &str, expected: &[u8]) -> Result<(), VaultStoreError> {
    let actual = read_artifact(directory, name)?
        .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))?;
    if actual.as_slice() == expected {
        Ok(())
    } else {
        Err(VaultStoreError::new(VaultStoreErrorKind::IoFailure))
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn validate_destination_state(
    directory: &Path,
    destination: &str,
    expected: DestinationState,
) -> Result<(), VaultStoreError> {
    let exists = artifact_exists(directory, destination)?;
    match (exists, expected) {
        (false, DestinationState::Absent) | (true, DestinationState::Present) => Ok(()),
        (true, DestinationState::Absent) => {
            Err(VaultStoreError::new(VaultStoreErrorKind::Conflict))
        }
        (false, DestinationState::Present) => {
            Err(VaultStoreError::new(VaultStoreErrorKind::MissingState))
        }
    }
}

fn temporary_name() -> Result<String, VaultStoreError> {
    let mut random = [0; 16];
    getrandom::fill(&mut random)
        .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::IoFailure))?;
    let mut name = String::from(".gschrank-write-");
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(".tmp");
    Ok(name)
}

fn validate_directory(metadata: &Metadata) -> Result<(), VaultStoreError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != system::effective_user_id()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(VaultStoreError::new(VaultStoreErrorKind::UnsafePath));
    }
    Ok(())
}

fn validate_regular_file(metadata: &Metadata) -> Result<(), VaultStoreError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != system::effective_user_id()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(VaultStoreError::new(VaultStoreErrorKind::UnsafePath));
    }
    Ok(())
}

fn map_directory_io(error: io::Error) -> VaultStoreError {
    map_io(error, VaultStoreErrorKind::IoFailure)
}

fn map_file_io(error: io::Error) -> VaultStoreError {
    map_io(error, VaultStoreErrorKind::IoFailure)
}

fn map_lock_io(error: io::Error) -> VaultStoreError {
    map_io(error, VaultStoreErrorKind::LockFailure)
}

fn map_io(error: io::Error, fallback: VaultStoreErrorKind) -> VaultStoreError {
    let io_kind = error.kind();
    let native_code = error.raw_os_error();
    // Deliberately discard the platform error text at this boundary. Only the
    // semantic category and optional numeric code may reach user-facing layers.
    drop(error);
    let kind = match (io_kind, native_code) {
        (_, Some(libc::ELOOP)) => VaultStoreErrorKind::UnsafePath,
        (io::ErrorKind::PermissionDenied, _) => VaultStoreErrorKind::PermissionDenied,
        (io::ErrorKind::AlreadyExists, _) => VaultStoreErrorKind::Conflict,
        _ => fallback,
    };
    native_code.map_or_else(
        || VaultStoreError::new(kind),
        |code| VaultStoreError::with_native_code(kind, code),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    use super::*;
    use crate::{
        EnvironmentName, Mutation, ProfileName, SecretValue,
        init::{InitOutcome, Initializer},
        key_provider::InteractionPolicy,
        profiles::{ProfileOperationError, ProfileOperations},
        recovery::{RecoveryAuthentication, RecoveryOperations},
        testing::MemoryKeyProvider,
        vault_store::{
            RecoveryArtifacts, RecoveryBundleId, RecoveryBundleMetadata, RecoveryReason,
        },
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("gschrank-store-test-{}-{id}", std::process::id()));
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(&root).unwrap();
            Self(root)
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
    fn creates_restrictive_artifacts_and_promotes_pending_atomically() {
        let test = TestDirectory::new();
        let store = LocalVaultStore::new(test.data());
        store
            .initialization_transaction::<_, VaultStoreError, _>(|transaction| {
                transaction.create_init_pending(b"encrypted-envelope")?;
                assert_eq!(
                    transaction.read_init_pending()?.unwrap().as_slice(),
                    b"encrypted-envelope"
                );
                assert_eq!(
                    transaction.promote_init_pending()?,
                    CommitOutcome::Committed
                );
                assert_eq!(
                    transaction.read_live()?.unwrap().as_slice(),
                    b"encrypted-envelope"
                );
                assert_eq!(
                    transaction.replace_live(b"replacement-envelope")?,
                    CommitOutcome::Committed
                );
                assert_eq!(
                    transaction.read_live()?.unwrap().as_slice(),
                    b"replacement-envelope"
                );
                Ok(())
            })
            .unwrap();

        assert_eq!(
            fs::metadata(test.data()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in [LOCK_FILE, LIVE_FILE] {
            assert_eq!(
                fs::metadata(test.data().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(!test.data().join(INIT_PENDING_FILE).exists());
    }

    #[test]
    fn preserves_exact_recovery_bundles_with_restrictive_durable_structure() {
        let test = TestDirectory::new();
        let store = LocalVaultStore::new(test.data());
        let metadata = RecoveryBundleMetadata {
            id: RecoveryBundleId::from_bytes([0x5a; 16]),
            created_at_unix_seconds: 1_765_000_000,
            reason: RecoveryReason::Reset,
        };
        let live = b"opaque-live-envelope";
        let pending = b"opaque-init-envelope";

        store
            .initialization_transaction::<_, VaultStoreError, _>(|transaction| {
                assert_eq!(
                    transaction.preserve_recovery(
                        metadata,
                        RecoveryArtifacts {
                            live: Some(live),
                            init_pending: Some(pending),
                        },
                    )?,
                    CommitOutcome::Committed
                );
                Ok(())
            })
            .unwrap();

        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].metadata, metadata);
        assert_eq!(bundles[0].live.as_ref().unwrap().as_slice(), live);
        assert_eq!(
            bundles[0].init_pending.as_ref().unwrap().as_slice(),
            pending
        );

        let recovery = test.data().join(RECOVERY_DIRECTORY);
        let bundle = recovery.join(metadata.id.to_hex());
        assert_eq!(
            fs::metadata(&recovery).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&bundle).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in [
            RECOVERY_MANIFEST_FILE,
            RECOVERY_LIVE_FILE,
            RECOVERY_INIT_FILE,
        ] {
            assert_eq!(
                fs::metadata(bundle.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read_dir(recovery).unwrap().count(), 1);
    }

    #[test]
    fn recovery_manifest_round_trips_all_reasons_and_rejects_noncanonical_bytes() {
        for (reason, expected_reason) in [
            (RecoveryReason::Restore, RecoveryReason::Restore),
            (RecoveryReason::Reset, RecoveryReason::Reset),
            (RecoveryReason::Rebuild, RecoveryReason::Rebuild),
        ] {
            let metadata = RecoveryBundleMetadata {
                id: RecoveryBundleId::from_bytes([9; 16]),
                created_at_unix_seconds: u64::MAX,
                reason,
            };
            let artifacts = RecoveryArtifacts {
                live: Some(b"live"),
                init_pending: Some(b"pending"),
            };
            let encoded = encode_recovery_manifest(metadata, artifacts);
            let (decoded, flags) = decode_recovery_manifest(&encoded).unwrap();
            assert_eq!(decoded.reason, expected_reason);
            assert_eq!(decoded, metadata);
            assert_eq!(flags, RECOVERY_FLAG_LIVE | RECOVERY_FLAG_INIT);
        }

        let metadata = RecoveryBundleMetadata {
            id: RecoveryBundleId::from_bytes([1; 16]),
            created_at_unix_seconds: 1,
            reason: RecoveryReason::Restore,
        };
        let mut noncanonical = encode_recovery_manifest(
            metadata,
            RecoveryArtifacts {
                live: Some(b"live"),
                init_pending: None,
            },
        );
        noncanonical[39] = 1;
        assert!(decode_recovery_manifest(&noncanonical).is_err());
        noncanonical[39] = 0;
        noncanonical[11] = 0;
        assert!(decode_recovery_manifest(&noncanonical).is_err());
    }

    #[test]
    fn authenticated_recovery_round_trip_keeps_canary_values_encrypted() {
        let test = TestDirectory::new();
        let keys = MemoryKeyProvider::new();
        let store = LocalVaultStore::new(test.data());
        Initializer::new(&keys, &store)
            .initialize(InteractionPolicy::FailFast)
            .unwrap();
        let profiles = ProfileOperations::new(&keys, &store);
        let profile = ProfileName::new("private").unwrap();
        profiles
            .create(profile.clone(), InteractionPolicy::FailFast)
            .unwrap();
        profiles
            .set(
                &profile,
                EnvironmentName::new("TOKEN").unwrap(),
                SecretValue::from_string("CANARY-recovery-secret".to_owned()).unwrap(),
                InteractionPolicy::FailFast,
            )
            .unwrap();
        let live = store
            .shared_read::<_, VaultStoreError, _>(|read| {
                read.read_live()?
                    .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))
            })
            .unwrap();
        let metadata = RecoveryBundleMetadata {
            id: RecoveryBundleId::from_bytes([0x33; 16]),
            created_at_unix_seconds: 1_765_000_001,
            reason: RecoveryReason::Rebuild,
        };
        store
            .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                transaction.preserve_recovery(
                    metadata,
                    RecoveryArtifacts {
                        live: Some(&live),
                        init_pending: None,
                    },
                )?;
                Ok(())
            })
            .unwrap();

        let recovered = fs::read(
            test.data()
                .join(RECOVERY_DIRECTORY)
                .join(metadata.id.to_hex())
                .join(RECOVERY_LIVE_FILE),
        )
        .unwrap();
        assert_eq!(recovered, live.as_slice());
        assert!(!recovered.windows(6).any(|window| window == b"CANARY"));
        let listed = RecoveryOperations::new(&keys, &store)
            .list(InteractionPolicy::FailFast)
            .unwrap();
        assert_eq!(
            listed.bundles[0].authentication,
            RecoveryAuthentication::Authenticated
        );
    }

    #[test]
    fn freezes_ambiguous_or_unsafe_recovery_directory_state() {
        let unexpected = TestDirectory::new();
        let store = LocalVaultStore::new(unexpected.data());
        store
            .initialization_transaction::<_, VaultStoreError, _>(|_| Ok(()))
            .unwrap();
        let recovery = unexpected.data().join(RECOVERY_DIRECTORY);
        let mut builder = DirBuilder::new();
        builder.mode(0o700).create(&recovery).unwrap();
        builder
            .mode(0o700)
            .create(recovery.join(".gschrank-recovery-abandoned.pending"))
            .unwrap();
        let result =
            store.shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles());
        assert!(matches!(
            result,
            Err(error) if error.kind() == VaultStoreErrorKind::Conflict
        ));

        let linked = TestDirectory::new();
        let store = LocalVaultStore::new(linked.data());
        store
            .initialization_transaction::<_, VaultStoreError, _>(|_| Ok(()))
            .unwrap();
        let outside = linked.0.join("outside-recovery");
        builder.mode(0o700).create(&outside).unwrap();
        symlink(&outside, linked.data().join(RECOVERY_DIRECTORY)).unwrap();
        let result =
            store.shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles());
        assert!(matches!(
            result,
            Err(error) if error.kind() == VaultStoreErrorKind::UnsafePath
        ));
    }

    #[test]
    fn rejects_an_existing_broadly_accessible_directory() {
        let test = TestDirectory::new();
        fs::create_dir(test.data()).unwrap();
        fs::set_permissions(test.data(), fs::Permissions::from_mode(0o755)).unwrap();
        let store = LocalVaultStore::new(test.data());
        let error = store
            .initialization_transaction::<_, VaultStoreError, _>(|_| Ok(()))
            .unwrap_err();
        assert_eq!(error.kind(), VaultStoreErrorKind::UnsafePath);
    }

    #[test]
    fn ordinary_reads_and_mutations_do_not_create_missing_store_state() {
        let test = TestDirectory::new();
        let store = LocalVaultStore::new(test.data());

        let read_error = store
            .shared_read::<_, VaultStoreError, _>(|transaction| transaction.read_live())
            .unwrap_err();
        assert_eq!(read_error.kind(), VaultStoreErrorKind::MissingState);
        assert!(!test.data().exists());

        let mutation_error = store
            .exclusive_transaction::<_, VaultStoreError, _>(|_| Ok(()))
            .unwrap_err();
        assert_eq!(mutation_error.kind(), VaultStoreErrorKind::MissingState);
        assert!(!test.data().exists());

        let keys = MemoryKeyProvider::new();
        let profile_error = ProfileOperations::new(&keys, &store)
            .list(InteractionPolicy::FailFast)
            .unwrap_err();
        assert_eq!(profile_error, ProfileOperationError::NotInitialized);
        assert_eq!(profile_error.exit_code(), 10);
        assert!(!test.data().exists());
    }

    #[test]
    fn a_preferences_only_data_directory_still_reports_an_uninitialized_vault() {
        let test = TestDirectory::new();
        let mut builder = DirBuilder::new();
        builder.mode(0o700).create(test.data()).unwrap();
        let store = LocalVaultStore::new(test.data());

        let error = store
            .shared_read::<_, VaultStoreError, _>(|transaction| transaction.read_live())
            .unwrap_err();
        assert_eq!(error.kind(), VaultStoreErrorKind::MissingState);
        assert!(!test.data().join(LOCK_FILE).exists());
    }

    #[test]
    fn rejects_symlinked_data_directory_and_vault_artifact() {
        let test = TestDirectory::new();
        let real_directory = test.0.join("real-data");
        let mut builder = DirBuilder::new();
        builder.mode(0o700).create(&real_directory).unwrap();
        symlink(&real_directory, test.data()).unwrap();

        let symlinked_store = LocalVaultStore::new(test.data());
        let error = symlinked_store
            .initialization_transaction::<_, VaultStoreError, _>(|_| Ok(()))
            .unwrap_err();
        assert_eq!(error.kind(), VaultStoreErrorKind::UnsafePath);

        fs::remove_file(test.data()).unwrap();
        let store = LocalVaultStore::new(test.data());
        store
            .initialization_transaction::<_, VaultStoreError, _>(|_| Ok(()))
            .unwrap();
        let target = test.0.join("outside-vault");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options.open(&target).unwrap();
        symlink(&target, test.data().join(LIVE_FILE)).unwrap();

        let error = store
            .shared_read::<_, VaultStoreError, _>(|transaction| transaction.read_live())
            .unwrap_err();
        assert_eq!(error.kind(), VaultStoreErrorKind::UnsafePath);
    }

    #[test]
    fn real_local_store_supports_complete_idempotent_initialization() {
        let test = TestDirectory::new();
        let keys = MemoryKeyProvider::new();
        let store = LocalVaultStore::new(test.data());
        let initializer = Initializer::new(&keys, &store);

        let InitOutcome::Created { vault_id, key_id } =
            initializer.initialize(InteractionPolicy::FailFast).unwrap()
        else {
            panic!("expected a new vault");
        };
        assert_eq!(
            initializer.initialize(InteractionPolicy::FailFast).unwrap(),
            InitOutcome::AlreadyInitialized {
                vault_id,
                key_id,
                revision: 0,
            }
        );

        let profiles = ProfileOperations::new(&keys, &store);
        profiles
            .create(
                ProfileName::new("dev").unwrap(),
                InteractionPolicy::FailFast,
            )
            .unwrap();
        assert_eq!(
            profiles.list(InteractionPolicy::FailFast).unwrap(),
            vec![ProfileName::new("dev").unwrap()]
        );

        let dev = ProfileName::new("dev").unwrap();
        let variable = EnvironmentName::new("TOKEN").unwrap();
        let set = profiles
            .set(
                &dev,
                variable.clone(),
                SecretValue::from_string("CANARY-production-store-$()`".to_owned()).unwrap(),
                InteractionPolicy::FailFast,
            )
            .unwrap();
        assert_eq!(set.mutation, Mutation::Created);
        assert_eq!(
            profiles
                .inspect(&dev, InteractionPolicy::FailFast)
                .unwrap()
                .variables,
            vec![variable]
        );
        for entry in fs::read_dir(test.data()).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(
                    !bytes.windows(6).any(|window| window == b"CANARY"),
                    "vault-store artifact exposed secret bytes"
                );
            }
        }
    }

    #[test]
    fn stable_lock_serializes_exclusive_transactions() {
        let test = TestDirectory::new();
        let store = Arc::new(LocalVaultStore::new(test.data()));
        store
            .initialization_transaction::<_, VaultStoreError, _>(|_| Ok(()))
            .unwrap();

        let (held_sender, held_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let first_store = Arc::clone(&store);
        let first = thread::spawn(move || {
            first_store
                .exclusive_transaction::<_, VaultStoreError, _>(|_| {
                    held_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                    Ok(())
                })
                .unwrap();
        });
        held_receiver.recv_timeout(Duration::from_secs(2)).unwrap();

        let (entered_sender, entered_receiver) = mpsc::channel();
        let second_store = Arc::clone(&store);
        let second = thread::spawn(move || {
            second_store
                .exclusive_transaction::<_, VaultStoreError, _>(|_| {
                    entered_sender.send(()).unwrap();
                    Ok(())
                })
                .unwrap();
        });

        assert!(
            entered_receiver
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        release_sender.send(()).unwrap();
        entered_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        first.join().unwrap();
        second.join().unwrap();
    }
}
