#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use crate::{ProfileName, VaultId, profile_rename::ProfileRenameIntent};

use super::system;

const LOCK_FILE: &str = "operation.lock";
const INTENT_FILE: &str = "profile-rename.pending";
const MAGIC: &[u8; 16] = b"GSCHRANK-RENAME\0";
const VERSION: u16 = 1;
const HEADER_LENGTH: usize = 44;
const MAX_PATH_BYTES: usize = 8 * 1024;
const MAX_INTENT_BYTES: usize = 16 * 1024;
const TEMP_PREFIX: &str = ".gschrank-rename-";
const TEMP_SUFFIX: &str = ".tmp";
const TEMP_ATTEMPTS: usize = 16;
const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) struct ApplicationOperationLock {
    directory: PathBuf,
    _lock: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationLockMode {
    Wait,
    FailFast,
}

impl ApplicationOperationLock {
    pub(crate) fn acquire(
        directory: PathBuf,
        create: bool,
        mode: OperationLockMode,
    ) -> Result<Option<Self>, ProfileRenameStoreError> {
        if !prepare_directory(&directory, create)? {
            return Ok(None);
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let lock = options.open(directory.join(LOCK_FILE)).map_err(map_io)?;
        validate_regular(&lock)?;
        match mode {
            OperationLockMode::Wait => lock
                .lock()
                .map_err(|_| ProfileRenameStoreError::LockFailure)?,
            OperationLockMode::FailFast => lock
                .try_lock()
                .map_err(|_| ProfileRenameStoreError::LockFailure)?,
        }
        sync_directory(&directory).map_err(map_io)?;
        Ok(Some(Self {
            directory,
            _lock: lock,
        }))
    }

    pub(crate) fn read_intent(
        &self,
    ) -> Result<Option<ProfileRenameIntent>, ProfileRenameStoreError> {
        cleanup_temporaries(&self.directory)?;
        let Some(bytes) = read_optional(&self.directory.join(INTENT_FILE))? else {
            return Ok(None);
        };
        decode(&bytes).map(Some)
    }

    pub(crate) fn create_intent(
        &self,
        intent: &ProfileRenameIntent,
    ) -> Result<(), ProfileRenameStoreError> {
        if let Some(existing) = self.read_intent()? {
            return if &existing == intent {
                Ok(())
            } else {
                Err(ProfileRenameStoreError::Conflict)
            };
        }
        let bytes = encode(intent)?;
        let temporary = TemporaryFile::write(&self.directory, &bytes)?;
        match fs::hard_link(temporary.path(), self.directory.join(INTENT_FILE)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(ProfileRenameStoreError::Conflict);
            }
            Err(error) => return Err(map_io(error)),
        }
        if sync_directory(&self.directory).is_err() {
            return Err(ProfileRenameStoreError::OutcomeIndeterminate);
        }
        match self.read_intent() {
            Ok(Some(committed)) if committed == *intent => Ok(()),
            _ => Err(ProfileRenameStoreError::OutcomeIndeterminate),
        }
    }

    pub(crate) fn remove_intent(
        &self,
        expected: &ProfileRenameIntent,
    ) -> Result<(), ProfileRenameStoreError> {
        match self.read_intent()? {
            Some(current) if current == *expected => {}
            Some(_) => return Err(ProfileRenameStoreError::Conflict),
            None => return Ok(()),
        }
        fs::remove_file(self.directory.join(INTENT_FILE)).map_err(map_io)?;
        if sync_directory(&self.directory).is_err() {
            return Err(ProfileRenameStoreError::OutcomeIndeterminate);
        }
        match self.read_intent() {
            Ok(None) => Ok(()),
            _ => Err(ProfileRenameStoreError::OutcomeIndeterminate),
        }
    }
}

fn prepare_directory(path: &Path, create: bool) -> Result<bool, ProfileRenameStoreError> {
    let mut created = false;
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_directory(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(path).map_err(map_io)?;
            validate_directory(&fs::symlink_metadata(path).map_err(map_io)?)?;
            created = true;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(map_io(error)),
    }
    if !system::is_apfs(path).map_err(map_io)? {
        return Err(ProfileRenameStoreError::UnsupportedStorage);
    }
    if created {
        let parent = path.parent().ok_or(ProfileRenameStoreError::UnsafePath)?;
        sync_directory(parent).map_err(|_| ProfileRenameStoreError::OutcomeIndeterminate)?;
    }
    Ok(true)
}

fn encode(intent: &ProfileRenameIntent) -> Result<Vec<u8>, ProfileRenameStoreError> {
    let old = intent.old.as_str().as_bytes();
    let new = intent.new.as_str().as_bytes();
    let path = intent.rc_file.as_os_str().as_bytes();
    if intent.old == intent.new
        || !intent.rc_file.is_absolute()
        || intent.rc_file.file_name().is_none()
        || path.is_empty()
        || path.len() > MAX_PATH_BYTES
    {
        return Err(ProfileRenameStoreError::InvalidFormat);
    }
    let mut bytes = Vec::with_capacity(HEADER_LENGTH + old.len() + new.len() + path.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(intent.vault_id.as_bytes());
    bytes.push(u8::from(intent.shortcut));
    bytes.push(u8::try_from(old.len()).map_err(|_| ProfileRenameStoreError::InvalidFormat)?);
    bytes.push(u8::try_from(new.len()).map_err(|_| ProfileRenameStoreError::InvalidFormat)?);
    bytes.push(0);
    bytes.extend_from_slice(
        &u32::try_from(path.len())
            .map_err(|_| ProfileRenameStoreError::InvalidFormat)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(old);
    bytes.extend_from_slice(new);
    bytes.extend_from_slice(path);
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<ProfileRenameIntent, ProfileRenameStoreError> {
    if bytes.len() < HEADER_LENGTH
        || bytes.len() > MAX_INTENT_BYTES
        || &bytes[..16] != MAGIC
        || u16::from_be_bytes([bytes[16], bytes[17]]) != VERSION
        || bytes[18..20] != [0, 0]
        || bytes[36] > 1
        || bytes[39] != 0
    {
        return Err(ProfileRenameStoreError::InvalidFormat);
    }
    let old_length = usize::from(bytes[37]);
    let new_length = usize::from(bytes[38]);
    let path_length = usize::try_from(u32::from_be_bytes(
        bytes[40..44]
            .try_into()
            .map_err(|_| ProfileRenameStoreError::InvalidFormat)?,
    ))
    .map_err(|_| ProfileRenameStoreError::InvalidFormat)?;
    let expected = HEADER_LENGTH
        .checked_add(old_length)
        .and_then(|length| length.checked_add(new_length))
        .and_then(|length| length.checked_add(path_length))
        .ok_or(ProfileRenameStoreError::InvalidFormat)?;
    if bytes.len() != expected
        || old_length == 0
        || new_length == 0
        || path_length == 0
        || path_length > MAX_PATH_BYTES
    {
        return Err(ProfileRenameStoreError::InvalidFormat);
    }
    let old_end = HEADER_LENGTH + old_length;
    let new_end = old_end + new_length;
    let old = std::str::from_utf8(&bytes[HEADER_LENGTH..old_end])
        .ok()
        .and_then(|name| ProfileName::new(name).ok())
        .ok_or(ProfileRenameStoreError::InvalidFormat)?;
    let new = std::str::from_utf8(&bytes[old_end..new_end])
        .ok()
        .and_then(|name| ProfileName::new(name).ok())
        .ok_or(ProfileRenameStoreError::InvalidFormat)?;
    let rc_file = PathBuf::from(OsString::from_vec(bytes[new_end..].to_vec()));
    if old == new || !rc_file.is_absolute() || rc_file.file_name().is_none() {
        return Err(ProfileRenameStoreError::InvalidFormat);
    }
    let mut vault_id = [0_u8; 16];
    vault_id.copy_from_slice(&bytes[20..36]);
    Ok(ProfileRenameIntent {
        vault_id: VaultId::from_bytes(vault_id),
        old,
        new,
        rc_file,
        shortcut: bytes[36] == 1,
    })
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, ProfileRenameStoreError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_io(error)),
    };
    validate_regular(&file)?;
    let mut bytes = Vec::new();
    file.take((MAX_INTENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() > MAX_INTENT_BYTES {
        Err(ProfileRenameStoreError::InvalidFormat)
    } else {
        Ok(Some(bytes))
    }
}

fn cleanup_temporaries(directory: &Path) -> Result<(), ProfileRenameStoreError> {
    let mut changed = false;
    for entry in fs::read_dir(directory).map_err(map_io)? {
        let entry = entry.map_err(map_io)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(ProfileRenameStoreError::Conflict)?;
        if is_temporary_name(name) {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(entry.path())
                .map_err(map_io)?;
            validate_regular(&file)?;
            fs::remove_file(entry.path()).map_err(map_io)?;
            changed = true;
        }
    }
    if changed {
        sync_directory(directory).map_err(map_io)?;
    }
    Ok(())
}

fn is_temporary_name(name: &str) -> bool {
    name.len() == TEMP_PREFIX.len() + 32 + TEMP_SUFFIX.len()
        && name.starts_with(TEMP_PREFIX)
        && name.ends_with(TEMP_SUFFIX)
        && name[TEMP_PREFIX.len()..TEMP_PREFIX.len() + 32]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

struct TemporaryFile(PathBuf);

impl TemporaryFile {
    fn write(directory: &Path, bytes: &[u8]) -> Result<Self, ProfileRenameStoreError> {
        for _ in 0..TEMP_ATTEMPTS {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|_| ProfileRenameStoreError::IoFailure)?;
            let mut name = String::from(TEMP_PREFIX);
            for byte in random {
                name.push(char::from(HEX[usize::from(byte >> 4)]));
                name.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
            name.push_str(TEMP_SUFFIX);
            let path = directory.join(name);
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
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(map_io)?;
            file.write_all(bytes).map_err(map_io)?;
            file.flush().map_err(map_io)?;
            system::full_sync(&file).map_err(map_io)?;
            return Ok(Self(path));
        }
        Err(ProfileRenameStoreError::IoFailure)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn validate_directory(metadata: &fs::Metadata) -> Result<(), ProfileRenameStoreError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != system::effective_user_id()
        || metadata.mode() & 0o7777 != 0o700
    {
        Err(ProfileRenameStoreError::UnsafePath)
    } else {
        Ok(())
    }
}

fn validate_regular(file: &File) -> Result<(), ProfileRenameStoreError> {
    let metadata = file.metadata().map_err(map_io)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != system::effective_user_id()
        || metadata.mode() & 0o7777 != 0o600
    {
        Err(ProfileRenameStoreError::UnsafePath)
    } else {
        Ok(())
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[allow(clippy::needless_pass_by_value)]
fn map_io(error: io::Error) -> ProfileRenameStoreError {
    match (error.kind(), error.raw_os_error()) {
        (_, Some(libc::ELOOP)) => ProfileRenameStoreError::UnsafePath,
        (io::ErrorKind::PermissionDenied, _) => ProfileRenameStoreError::PermissionDenied,
        _ => ProfileRenameStoreError::IoFailure,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileRenameStoreError {
    UnsafePath,
    UnsupportedStorage,
    InvalidFormat,
    Conflict,
    PermissionDenied,
    LockFailure,
    IoFailure,
    OutcomeIndeterminate,
}

impl ProfileRenameStoreError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::UnsafePath | Self::UnsupportedStorage | Self::PermissionDenied => 13,
            Self::InvalidFormat | Self::Conflict => 14,
            Self::OutcomeIndeterminate => 15,
            Self::LockFailure | Self::IoFailure => 1,
        }
    }
}

impl fmt::Display for ProfileRenameStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "the profile-rename transaction path is unsafe",
            Self::UnsupportedStorage => {
                "the profile-rename transaction requires supported local storage"
            }
            Self::InvalidFormat => "the pending profile-rename transaction is invalid",
            Self::Conflict => "the pending profile-rename transaction conflicts with current state",
            Self::PermissionDenied => {
                "permission to access the profile-rename transaction was denied"
            }
            Self::LockFailure => "the profile-rename transaction could not be locked",
            Self::IoFailure => "the profile-rename transaction could not be accessed",
            Self::OutcomeIndeterminate => "the profile-rename transaction outcome is indeterminate",
        })
    }
}

impl std::error::Error for ProfileRenameStoreError {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "gschrank-profile-rename-test-{}-{id}",
                std::process::id()
            ));
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn intent(test: &TestDirectory) -> ProfileRenameIntent {
        ProfileRenameIntent {
            vault_id: VaultId::from_bytes([3; 16]),
            old: ProfileName::new("work").unwrap(),
            new: ProfileName::new("office").unwrap(),
            rc_file: test.0.join(".zshrc"),
            shortcut: true,
        }
    }

    #[test]
    fn round_trips_one_restrictive_create_only_intent() {
        let test = TestDirectory::new();
        let lock = ApplicationOperationLock::acquire(test.0.clone(), true, OperationLockMode::Wait)
            .unwrap()
            .unwrap();
        let expected = intent(&test);
        lock.create_intent(&expected).unwrap();
        assert_eq!(lock.read_intent().unwrap(), Some(expected.clone()));
        assert_eq!(
            fs::metadata(test.0.join(INTENT_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut conflicting = expected.clone();
        conflicting.new = ProfileName::new("other").unwrap();
        assert_eq!(
            lock.create_intent(&conflicting).unwrap_err(),
            ProfileRenameStoreError::Conflict
        );
        lock.remove_intent(&expected).unwrap();
        assert_eq!(lock.read_intent().unwrap(), None);
    }

    #[test]
    fn strict_codec_rejects_truncation_and_secret_canary_is_absent() {
        let test = TestDirectory::new();
        let expected = intent(&test);
        let bytes = encode(&expected).unwrap();
        assert!(!bytes.windows(6).any(|window| window == b"CANARY"));
        for length in 0..bytes.len() {
            assert_eq!(
                decode(&bytes[..length]).unwrap_err(),
                ProfileRenameStoreError::InvalidFormat
            );
        }
        assert_eq!(decode(&bytes).unwrap(), expected);

        let path_start = HEADER_LENGTH + 4 + 6;
        let mut oversized = bytes;
        oversized.truncate(path_start);
        oversized.extend(std::iter::once(b'/').chain(std::iter::repeat_n(b'a', MAX_PATH_BYTES)));
        oversized[40..44]
            .copy_from_slice(&u32::try_from(MAX_PATH_BYTES + 1).unwrap().to_be_bytes());
        assert_eq!(
            decode(&oversized).unwrap_err(),
            ProfileRenameStoreError::InvalidFormat
        );
    }

    #[test]
    fn fail_fast_lock_refuses_contention_without_waiting() {
        let test = TestDirectory::new();
        let held = ApplicationOperationLock::acquire(test.0.clone(), true, OperationLockMode::Wait)
            .unwrap()
            .unwrap();
        assert!(matches!(
            ApplicationOperationLock::acquire(test.0.clone(), false, OperationLockMode::FailFast,),
            Err(ProfileRenameStoreError::LockFailure)
        ));
        drop(held);
        assert!(
            ApplicationOperationLock::acquire(test.0.clone(), false, OperationLockMode::FailFast)
                .unwrap()
                .is_some()
        );
    }
}
