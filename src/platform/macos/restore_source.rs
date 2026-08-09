#![forbid(unsafe_code)]

use std::{
    fs::{self, Metadata, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use zeroize::Zeroizing;

use crate::{MAX_ENVELOPE_SIZE, restore::RestoreSourceError};

use super::system;

/// Restrictive, bounded reading of one user-selected encrypted backup.
pub(crate) struct EncryptedRestoreSource {
    path: PathBuf,
}

impl EncryptedRestoreSource {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(crate) fn read(&self) -> Result<Zeroizing<Vec<u8>>, RestoreSourceError> {
        validate_path(&self.path)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options.open(&self.path).map_err(map_io)?;
        let metadata = file.metadata().map_err(map_io)?;
        validate_file(&metadata)?;
        if metadata.len() > MAX_ENVELOPE_SIZE as u64 {
            return Err(RestoreSourceError::IoFailure);
        }
        let capacity =
            usize::try_from(metadata.len()).map_err(|_| RestoreSourceError::IoFailure)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
        file.take((MAX_ENVELOPE_SIZE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(map_io)?;
        if bytes.len() > MAX_ENVELOPE_SIZE {
            return Err(RestoreSourceError::IoFailure);
        }
        Ok(bytes)
    }
}

fn validate_path(path: &Path) -> Result<(), RestoreSourceError> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(RestoreSourceError::UnsafePath);
    }
    for component in path.components() {
        if !matches!(component, Component::RootDir | Component::Normal(_)) {
            return Err(RestoreSourceError::UnsafePath);
        }
    }
    let parent = path.parent().ok_or(RestoreSourceError::UnsafePath)?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(map_io)?;
        if !metadata.file_type().is_dir() {
            return Err(RestoreSourceError::UnsafePath);
        }
    }
    Ok(())
}

fn validate_file(metadata: &Metadata) -> Result<(), RestoreSourceError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != system::effective_user_id()
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        Err(RestoreSourceError::UnsafePath)
    } else {
        Ok(())
    }
}

fn map_io(error: io::Error) -> RestoreSourceError {
    let kind = error.kind();
    let native = error.raw_os_error();
    drop(error);
    match (kind, native) {
        (io::ErrorKind::NotFound, _) => RestoreSourceError::NotFound,
        (_, Some(libc::ELOOP)) => RestoreSourceError::UnsafePath,
        (io::ErrorKind::PermissionDenied, _) => RestoreSourceError::PermissionDenied,
        _ => RestoreSourceError::IoFailure,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "gschrank-restore-source-test-{}-{id}",
                    std::process::id()
                ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(&root).unwrap();
            Self(root)
        }

        fn source(&self) -> PathBuf {
            self.0.join("vault.backup")
        }

        fn write_source(&self, bytes: &[u8]) {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options
                .open(self.source())
                .unwrap()
                .write_all(bytes)
                .unwrap();
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reads_exact_owned_restrictive_ciphertext_without_changing_the_source() {
        let test = TestDirectory::new();
        test.write_source(b"opaque-encrypted-envelope");

        let bytes = EncryptedRestoreSource::new(test.source()).read().unwrap();

        assert_eq!(bytes.as_slice(), b"opaque-encrypted-envelope");
        assert_eq!(fs::read(test.source()).unwrap(), bytes.as_slice());
    }

    #[test]
    fn rejects_relative_missing_broad_and_oversized_sources() {
        assert_eq!(
            EncryptedRestoreSource::new(PathBuf::from("relative.backup"))
                .read()
                .unwrap_err(),
            RestoreSourceError::UnsafePath
        );
        let missing = TestDirectory::new();
        assert_eq!(
            EncryptedRestoreSource::new(missing.source())
                .read()
                .unwrap_err(),
            RestoreSourceError::NotFound
        );
        let broad = TestDirectory::new();
        broad.write_source(b"encrypted");
        fs::set_permissions(broad.source(), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            EncryptedRestoreSource::new(broad.source())
                .read()
                .unwrap_err(),
            RestoreSourceError::UnsafePath
        );
        let oversized = TestDirectory::new();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let file = options.open(oversized.source()).unwrap();
        file.set_len((MAX_ENVELOPE_SIZE + 1) as u64).unwrap();
        assert_eq!(
            EncryptedRestoreSource::new(oversized.source())
                .read()
                .unwrap_err(),
            RestoreSourceError::IoFailure
        );
    }

    #[test]
    fn rejects_symlinked_source_and_parent_components() {
        let linked_source = TestDirectory::new();
        let target = linked_source.0.join("target");
        linked_source.write_source(b"unused");
        fs::rename(linked_source.source(), &target).unwrap();
        symlink(&target, linked_source.source()).unwrap();
        assert_eq!(
            EncryptedRestoreSource::new(linked_source.source())
                .read()
                .unwrap_err(),
            RestoreSourceError::UnsafePath
        );

        let linked_parent = TestDirectory::new();
        let real = linked_parent.0.join("real");
        fs::create_dir(&real).unwrap();
        let source = real.join("vault.backup");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options.open(&source).unwrap();
        let alias = linked_parent.0.join("alias");
        symlink(&real, &alias).unwrap();
        assert_eq!(
            EncryptedRestoreSource::new(alias.join("vault.backup"))
                .read()
                .unwrap_err(),
            RestoreSourceError::UnsafePath
        );
    }
}
