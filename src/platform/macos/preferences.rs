#![forbid(unsafe_code)]

use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, DirBuilder, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use super::system;

const CONFIG_FILE: &str = "config";
const LOCK_FILE: &str = "config.lock";
const MAGIC: &[u8] = b"GSCHRANK-CONFIG\0";
const VERSION: u16 = 1;
const SHORTCUT_ENABLED: u8 = 1;
const MAX_CONFIG_BYTES: usize = 16 * 1024;
const MAX_PATH_BYTES: usize = 8 * 1024;
const TEMP_ATTEMPTS: usize = 16;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Non-secret shell preferences kept outside shell startup files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShellPreferences {
    rc_file: PathBuf,
    shortcut: bool,
}

impl ShellPreferences {
    pub(crate) fn new(rc_file: PathBuf, shortcut: bool) -> Result<Self, PreferenceError> {
        validate_rc_path(&rc_file)?;
        Ok(Self { rc_file, shortcut })
    }

    pub(crate) fn rc_file(&self) -> &Path {
        &self.rc_file
    }

    pub(crate) const fn shortcut(&self) -> bool {
        self.shortcut
    }
}

/// Atomic, permission-validating storage for non-secret application preferences.
pub(crate) struct ShellPreferenceStore {
    directory: PathBuf,
}

impl ShellPreferenceStore {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub(crate) fn read(&self) -> Result<Option<ShellPreferences>, PreferenceError> {
        if !self.prepare_directory(false)? {
            return Ok(None);
        }

        let config_path = self.directory.join(CONFIG_FILE);
        match fs::symlink_metadata(&config_path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(map_file_io(error)),
        }
        let lock = self.open_lock(false)?;
        lock.lock_shared().map_err(map_lock_io)?;

        // Reopen under the lock so a concurrent atomic replacement cannot make
        // the pre-lock handle authoritative.
        let config =
            open_optional_regular(&config_path)?.ok_or(PreferenceError::ConcurrentChange)?;
        let bytes = read_config_bytes(config)?;
        decode(&bytes).map(Some)
    }

    pub(crate) fn write(&self, preferences: &ShellPreferences) -> Result<(), PreferenceError> {
        self.prepare_directory(true)?;
        let lock = self.open_lock(true)?;
        lock.lock().map_err(map_lock_io)?;
        let bytes = encode(preferences)?;
        // Refuse unsafe existing entries instead of replacing them as a side
        // effect of an otherwise valid preference update. Existing bytes must
        // also decode before they can be deliberately replaced.
        if let Some(existing) = open_optional_regular(&self.directory.join(CONFIG_FILE))? {
            let existing = read_config_bytes(existing)?;
            decode(&existing)?;
            if existing == bytes {
                return Ok(());
            }
        }

        let temporary = TemporaryFile::write(&self.directory, &bytes)?;
        fs::rename(temporary.path(), self.directory.join(CONFIG_FILE)).map_err(map_file_io)?;

        let committed = open_optional_regular(&self.directory.join(CONFIG_FILE))
            .map_err(|_| PreferenceError::OutcomeIndeterminate)?
            .ok_or(PreferenceError::OutcomeIndeterminate)?;
        let mut committed_bytes = Vec::new();
        committed
            .take((MAX_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut committed_bytes)
            .map_err(|_| PreferenceError::OutcomeIndeterminate)?;
        if committed_bytes != bytes {
            return Err(PreferenceError::OutcomeIndeterminate);
        }
        sync_directory(&self.directory).map_err(|_| PreferenceError::OutcomeIndeterminate)
    }

    pub(crate) fn remove(&self) -> Result<(), PreferenceError> {
        if !self.prepare_directory(false)? {
            return Ok(());
        }
        let config_path = self.directory.join(CONFIG_FILE);
        let config_exists = match fs::symlink_metadata(&config_path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(map_file_io(error)),
        };
        if !config_exists && config_temporary_paths(&self.directory)?.is_empty() {
            return Ok(());
        }
        let lock = self.open_lock(true)?;
        lock.lock().map_err(map_lock_io)?;

        let config = open_optional_regular(&config_path)?;
        if config_exists && config.is_none() {
            return Err(PreferenceError::ConcurrentChange);
        }
        let had_config = config.is_some();
        let temporary_paths = config_temporary_paths(&self.directory)?;
        for path in &temporary_paths {
            if open_optional_regular(path)?.is_none() {
                return Err(PreferenceError::ConcurrentChange);
            }
        }
        if let Some(config) = config {
            decode(&read_config_bytes(config)?)?;
        }

        let mut changed = false;
        if had_config {
            fs::remove_file(&config_path).map_err(map_file_io)?;
            changed = true;
        }
        for path in temporary_paths {
            if let Err(error) = fs::remove_file(path) {
                return if changed {
                    Err(PreferenceError::OutcomeIndeterminate)
                } else {
                    Err(map_file_io(error))
                };
            }
            changed = true;
        }
        if !changed {
            return Ok(());
        }
        sync_directory(&self.directory).map_err(|_| PreferenceError::OutcomeIndeterminate)?;
        if open_optional_regular(&config_path)
            .map_err(|_| PreferenceError::OutcomeIndeterminate)?
            .is_some()
            || !config_temporary_paths(&self.directory)
                .map_err(|_| PreferenceError::OutcomeIndeterminate)?
                .is_empty()
        {
            Err(PreferenceError::OutcomeIndeterminate)
        } else {
            Ok(())
        }
    }

    fn prepare_directory(&self, create: bool) -> Result<bool, PreferenceError> {
        let mut created = false;
        match fs::symlink_metadata(&self.directory) {
            Ok(metadata) => validate_directory(&metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                builder.create(&self.directory).map_err(map_directory_io)?;
                validate_directory(
                    &fs::symlink_metadata(&self.directory).map_err(map_directory_io)?,
                )?;
                created = true;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(map_directory_io(error)),
        }
        if !system::is_apfs(&self.directory).map_err(map_directory_io)? {
            return Err(PreferenceError::UnsupportedStorage);
        }
        if created {
            let parent = self.directory.parent().ok_or(PreferenceError::UnsafePath)?;
            sync_directory(parent).map_err(|_| PreferenceError::OutcomeIndeterminate)?;
        }
        Ok(true)
    }

    fn open_lock(&self, create: bool) -> Result<File, PreferenceError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(create)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options
            .open(self.directory.join(LOCK_FILE))
            .map_err(map_file_io)?;
        validate_regular(&file.metadata().map_err(map_file_io)?)?;
        Ok(file)
    }
}

fn encode(preferences: &ShellPreferences) -> Result<Vec<u8>, PreferenceError> {
    validate_rc_path(preferences.rc_file())?;
    let path = preferences.rc_file().as_os_str().as_bytes();
    if path.len() > MAX_PATH_BYTES {
        return Err(PreferenceError::UnsafePath);
    }
    let path_length = u32::try_from(path.len()).map_err(|_| PreferenceError::UnsafePath)?;
    let mut bytes = Vec::with_capacity(MAGIC.len() + 7 + path.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.push(u8::from(preferences.shortcut()));
    bytes.extend_from_slice(&path_length.to_le_bytes());
    bytes.extend_from_slice(path);
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<ShellPreferences, PreferenceError> {
    let header_length = MAGIC.len() + 2 + 1 + 4;
    if bytes.len() < header_length || &bytes[..MAGIC.len()] != MAGIC {
        return Err(PreferenceError::InvalidFormat);
    }
    let mut cursor = MAGIC.len();
    let version = u16::from_le_bytes(
        bytes[cursor..cursor + 2]
            .try_into()
            .map_err(|_| PreferenceError::InvalidFormat)?,
    );
    cursor += 2;
    if version != VERSION {
        return Err(PreferenceError::UnsupportedVersion);
    }
    let flags = bytes[cursor];
    cursor += 1;
    if flags & !SHORTCUT_ENABLED != 0 {
        return Err(PreferenceError::InvalidFormat);
    }
    let path_length = u32::from_le_bytes(
        bytes[cursor..cursor + 4]
            .try_into()
            .map_err(|_| PreferenceError::InvalidFormat)?,
    );
    cursor += 4;
    let path_length = usize::try_from(path_length).map_err(|_| PreferenceError::InvalidFormat)?;
    if path_length > MAX_PATH_BYTES || bytes.len() != cursor.saturating_add(path_length) {
        return Err(PreferenceError::InvalidFormat);
    }
    ShellPreferences::new(
        PathBuf::from(OsString::from_vec(bytes[cursor..].to_vec())),
        flags & SHORTCUT_ENABLED != 0,
    )
    .map_err(|_| PreferenceError::InvalidFormat)
}

fn validate_rc_path(path: &Path) -> Result<(), PreferenceError> {
    let bytes = path.as_os_str().as_bytes();
    if !path.is_absolute()
        || path.file_name().is_none()
        || bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
    {
        return Err(PreferenceError::UnsafePath);
    }
    Ok(())
}

fn open_optional_regular(path: &Path) -> Result<Option<File>, PreferenceError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_file_io(error)),
    };
    validate_regular(&file.metadata().map_err(map_file_io)?)?;
    Ok(Some(file))
}

fn read_config_bytes(config: File) -> Result<Vec<u8>, PreferenceError> {
    let metadata = config.metadata().map_err(map_file_io)?;
    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(PreferenceError::InvalidFormat);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| PreferenceError::InvalidFormat)?;
    let mut bytes = Vec::with_capacity(capacity);
    config
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_file_io)?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(PreferenceError::InvalidFormat);
    }
    Ok(bytes)
}

fn validate_directory(metadata: &Metadata) -> Result<(), PreferenceError> {
    if !metadata.file_type().is_dir()
        || metadata.uid() != system::effective_user_id()
        || metadata.mode() & 0o7777 != 0o700
    {
        Err(PreferenceError::UnsafePath)
    } else {
        Ok(())
    }
}

fn validate_regular(metadata: &Metadata) -> Result<(), PreferenceError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != system::effective_user_id()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        Err(PreferenceError::UnsafePath)
    } else {
        Ok(())
    }
}

struct TemporaryFile {
    path: PathBuf,
}

impl TemporaryFile {
    fn write(directory: &Path, bytes: &[u8]) -> Result<Self, PreferenceError> {
        for _ in 0..TEMP_ATTEMPTS {
            let path = directory.join(temporary_name()?);
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            let mut file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(map_file_io(error)),
            };
            let result = (|| {
                validate_regular(&file.metadata().map_err(map_file_io)?)?;
                file.set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(map_file_io)?;
                file.write_all(bytes).map_err(map_file_io)?;
                file.flush().map_err(map_file_io)?;
                system::full_sync(&file).map_err(map_file_io)
            })();
            if let Err(error) = result {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
            return Ok(Self { path });
        }
        Err(PreferenceError::IoFailure)
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn temporary_name() -> Result<String, PreferenceError> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| PreferenceError::IoFailure)?;
    let mut name = String::from(".gschrank-config-");
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(".tmp");
    Ok(name)
}

fn config_temporary_paths(directory: &Path) -> Result<Vec<PathBuf>, PreferenceError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory).map_err(map_directory_io)? {
        let entry = entry.map_err(map_directory_io)?;
        let name = entry.file_name();
        if is_config_temporary_name(name.as_bytes()) {
            paths.push(directory.join(name));
        }
    }
    paths.sort();
    Ok(paths)
}

fn is_config_temporary_name(name: &[u8]) -> bool {
    const PREFIX: &[u8] = b".gschrank-config-";
    const SUFFIX: &[u8] = b".tmp";
    name.len() == PREFIX.len() + 32 + SUFFIX.len()
        && name.starts_with(PREFIX)
        && name.ends_with(SUFFIX)
        && name[PREFIX.len()..PREFIX.len() + 32]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreferenceError {
    UnsafePath,
    UnsupportedStorage,
    InvalidFormat,
    UnsupportedVersion,
    ConcurrentChange,
    PermissionDenied,
    LockFailure,
    IoFailure,
    OutcomeIndeterminate,
}

impl PreferenceError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::UnsafePath | Self::UnsupportedStorage | Self::PermissionDenied => 13,
            Self::InvalidFormat | Self::UnsupportedVersion | Self::ConcurrentChange => 14,
            Self::OutcomeIndeterminate => 15,
            Self::LockFailure | Self::IoFailure => 1,
        }
    }
}

impl fmt::Display for PreferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "the saved shell configuration path is unsafe",
            Self::UnsupportedStorage => "the shell preferences require supported local storage",
            Self::InvalidFormat => "the saved shell preferences are invalid",
            Self::UnsupportedVersion => "the saved shell preferences use an unsupported version",
            Self::ConcurrentChange => "the shell preferences changed while they were being read",
            Self::PermissionDenied => "permission to access shell preferences was denied",
            Self::LockFailure => "the shell preferences could not be locked",
            Self::IoFailure => "the shell preferences could not be accessed",
            Self::OutcomeIndeterminate => {
                "the shell preference update outcome is indeterminate; inspect it before retrying"
            }
        })
    }
}

impl Error for PreferenceError {}

fn map_directory_io(error: io::Error) -> PreferenceError {
    map_io(error, PreferenceError::IoFailure)
}

fn map_file_io(error: io::Error) -> PreferenceError {
    map_io(error, PreferenceError::IoFailure)
}

fn map_lock_io(error: io::Error) -> PreferenceError {
    map_io(error, PreferenceError::LockFailure)
}

fn map_io(error: io::Error, fallback: PreferenceError) -> PreferenceError {
    let kind = error.kind();
    let native = error.raw_os_error();
    drop(error);
    match (kind, native) {
        (_, Some(libc::ELOOP)) => PreferenceError::UnsafePath,
        (io::ErrorKind::PermissionDenied, _) => PreferenceError::PermissionDenied,
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "gschrank-preference-test-{}-{id}",
                std::process::id()
            ));
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn round_trips_non_utf8_paths_with_restrictive_atomic_files() {
        let test = TestDirectory::new();
        let data = test.0.join("data");
        let store = ShellPreferenceStore::new(data.clone());
        assert_eq!(store.read().unwrap(), None);

        let path = PathBuf::from(OsString::from_vec(b"/tmp/zsh-\xff/.zshrc".to_vec()));
        let expected = ShellPreferences::new(path, true).unwrap();
        store.write(&expected).unwrap();
        let loaded = store.read().unwrap().unwrap();
        assert_eq!(loaded, expected);
        let first_inode = fs::metadata(data.join(CONFIG_FILE)).unwrap().ino();
        store.write(&loaded).unwrap();
        assert_eq!(
            fs::metadata(data.join(CONFIG_FILE)).unwrap().ino(),
            first_inode,
            "an unchanged preference must not be rewritten"
        );
        assert_eq!(
            fs::metadata(&data).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in [CONFIG_FILE, LOCK_FILE] {
            assert_eq!(
                fs::metadata(data.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn removes_valid_saved_preferences_idempotently_without_removing_the_lock() {
        let test = TestDirectory::new();
        let data = test.0.join("data");
        let store = ShellPreferenceStore::new(data.clone());
        store
            .write(&ShellPreferences::new(test.0.join(".zshrc"), true).unwrap())
            .unwrap();
        let interrupted = data.join(".gschrank-config-0102030405060708090a0b0c0d0e0f10.tmp");
        fs::write(&interrupted, b"interrupted preference write").unwrap();
        fs::set_permissions(&interrupted, fs::Permissions::from_mode(0o600)).unwrap();

        store.remove().unwrap();

        assert_eq!(store.read().unwrap(), None);
        assert!(!data.join(CONFIG_FILE).exists());
        assert!(!interrupted.exists());
        assert!(data.join(LOCK_FILE).is_file());
        store.remove().unwrap();
    }

    #[test]
    fn refuses_unsafe_config_temporaries_without_removing_preferences() {
        let test = TestDirectory::new();
        let data = test.0.join("data");
        let store = ShellPreferenceStore::new(data.clone());
        store
            .write(&ShellPreferences::new(test.0.join(".zshrc"), true).unwrap())
            .unwrap();
        let interrupted = data.join(".gschrank-config-11111111111111111111111111111111.tmp");
        fs::write(&interrupted, b"unsafe mode").unwrap();
        fs::set_permissions(&interrupted, fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(store.remove().unwrap_err(), PreferenceError::UnsafePath);
        assert!(data.join(CONFIG_FILE).is_file());
        assert!(interrupted.is_file());
    }

    #[test]
    fn rejects_malformed_and_symlinked_preference_files() {
        let test = TestDirectory::new();
        let data = test.0.join("data");
        let store = ShellPreferenceStore::new(data.clone());
        store
            .write(&ShellPreferences::new(test.0.join(".zshrc"), false).unwrap())
            .unwrap();
        fs::write(data.join(CONFIG_FILE), b"malformed").unwrap();
        assert_eq!(store.read().unwrap_err(), PreferenceError::InvalidFormat);
        assert_eq!(store.remove().unwrap_err(), PreferenceError::InvalidFormat);

        fs::remove_file(data.join(CONFIG_FILE)).unwrap();
        let target = test.0.join("outside");
        fs::write(&target, b"outside").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, data.join(CONFIG_FILE)).unwrap();
        assert_eq!(store.read().unwrap_err(), PreferenceError::UnsafePath);
        assert_eq!(
            store
                .write(&ShellPreferences::new(test.0.join(".zshrc"), true).unwrap())
                .unwrap_err(),
            PreferenceError::UnsafePath
        );
    }

    #[test]
    fn rejects_relative_paths_and_broad_directories() {
        assert_eq!(
            ShellPreferences::new(PathBuf::from(".zshrc"), true).unwrap_err(),
            PreferenceError::UnsafePath
        );

        let test = TestDirectory::new();
        let data = test.0.join("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
        let store = ShellPreferenceStore::new(data);
        assert_eq!(store.read().unwrap_err(), PreferenceError::UnsafePath);
    }
}
