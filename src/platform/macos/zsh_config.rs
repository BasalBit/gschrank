#![forbid(unsafe_code)]

use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    ops::Range,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::{
    ProfileName,
    shell::{
        ZSH_MANAGED_BLOCK_END, ZSH_MANAGED_BLOCK_START, ZSH_SHORTCUT_METADATA,
        ZSH_STARTUP_METADATA, ZshManagedBlock,
    },
    shell_config::{ShellConfigEdit, ShellIntegrationState, StartupConfiguration},
};

use super::system;

const MAX_STARTUP_FILE_BYTES: usize = 16 * 1024 * 1024;
const TEMP_ATTEMPTS: usize = 16;
const HEX: &[u8; 16] = b"0123456789abcdef";
const MANAGED_START_PREFIX: &[u8] = b"# >>> gschrank initialize";
const MANAGED_END_PREFIX: &[u8] = b"# <<< gschrank initialize";

/// Safe editor for Gschrank's single managed block in one Zsh startup file.
pub(crate) struct ZshConfigEditor {
    rc_file: PathBuf,
}

impl ZshConfigEditor {
    pub(crate) fn discover() -> Result<Self, ZshConfigError> {
        let directory = match std::env::var_os("ZDOTDIR") {
            Some(directory) if !directory.is_empty() => PathBuf::from(directory),
            Some(_) | None => system::home_directory().map_err(map_io)?,
        };
        if !directory.is_absolute() {
            return Err(ZshConfigError::UnsafePath);
        }
        Ok(Self {
            rc_file: directory.join(".zshrc"),
        })
    }

    pub(crate) fn at_path(rc_file: PathBuf) -> Self {
        Self { rc_file }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.rc_file
    }

    pub(crate) fn inspect(&self) -> Result<ShellIntegrationState, ZshConfigError> {
        let snapshot = self.read_snapshot()?;
        match parse_managed_block(snapshot.bytes())? {
            Some(parsed) => Ok(ShellIntegrationState::Installed(parsed.configuration)),
            None => Ok(ShellIntegrationState::Absent),
        }
    }

    pub(crate) fn configure(
        &self,
        block: &ZshManagedBlock,
    ) -> Result<ShellConfigEdit, ZshConfigError> {
        self.configure_with(block, || {})
    }

    fn configure_with(
        &self,
        block: &ZshManagedBlock,
        before_final_check: impl FnOnce(),
    ) -> Result<ShellConfigEdit, ZshConfigError> {
        let parsed_emission =
            parse_managed_block(block.source())?.ok_or(ZshConfigError::MalformedManagedBlock)?;
        if parsed_emission.range != (0..block.source().len())
            || &parsed_emission.configuration != block.configuration()
        {
            return Err(ZshConfigError::MalformedManagedBlock);
        }

        let snapshot = self.read_snapshot()?;
        let existing = parse_managed_block(snapshot.bytes())?;
        let managed_range = existing.as_ref().map(|parsed| parsed.range.clone());
        let enabling_shortcut = block.configuration().shortcut()
            && existing
                .as_ref()
                .is_none_or(|parsed| !parsed.configuration.shortcut());
        Self::check_command_conflicts(snapshot.bytes(), managed_range.as_ref(), enabling_shortcut)?;

        let replacement = replace_managed_block(snapshot.bytes(), managed_range, block.source());
        if replacement == snapshot.bytes() {
            return Ok(ShellConfigEdit::Unchanged);
        }

        let parent = self.validated_parent()?;
        let mode = snapshot.mode().unwrap_or(0o600);
        let temporary = TemporaryFile::write(&parent, &replacement, mode)?;
        before_final_check();
        self.verify_unchanged(&snapshot)?;
        self.ensure_first_backup(&parent, &snapshot)?;
        self.verify_unchanged(&snapshot)?;
        fs::rename(temporary.path(), &self.rc_file).map_err(map_io)?;

        let committed =
            read_regular_file(&self.rc_file)?.ok_or(ZshConfigError::OutcomeIndeterminate)?;
        if committed.bytes != replacement {
            return Err(ZshConfigError::OutcomeIndeterminate);
        }
        sync_directory(&parent).map_err(|_| ZshConfigError::OutcomeIndeterminate)?;

        Ok(if existing.is_some() {
            ShellConfigEdit::Updated
        } else {
            ShellConfigEdit::Installed
        })
    }

    fn read_snapshot(&self) -> Result<SourceSnapshot, ZshConfigError> {
        self.validated_parent()?;
        if path_exists_safely(&compiled_path(&self.rc_file))? {
            return Err(ZshConfigError::ShadowedByCompiledFile);
        }
        Ok(match read_regular_file(&self.rc_file)? {
            Some(file) => SourceSnapshot::Present(file),
            None => SourceSnapshot::Missing,
        })
    }

    fn validated_parent(&self) -> Result<PathBuf, ZshConfigError> {
        if !self.rc_file.is_absolute() || self.rc_file.file_name().is_none() {
            return Err(ZshConfigError::UnsafePath);
        }
        let parent = self.rc_file.parent().ok_or(ZshConfigError::UnsafePath)?;
        let metadata = fs::symlink_metadata(parent).map_err(map_io)?;
        if !metadata.file_type().is_dir() || metadata.uid() != system::effective_user_id() {
            return Err(ZshConfigError::UnsafePath);
        }
        Ok(parent.to_owned())
    }

    fn verify_unchanged(&self, snapshot: &SourceSnapshot) -> Result<(), ZshConfigError> {
        if path_exists_safely(&compiled_path(&self.rc_file))? {
            return Err(ZshConfigError::ShadowedByCompiledFile);
        }
        let current = match read_regular_file(&self.rc_file) {
            Ok(current) => current,
            Err(ZshConfigError::IoFailure | ZshConfigError::PermissionDenied) => {
                return Err(ZshConfigError::ConcurrentModification);
            }
            Err(error) => return Err(error),
        };
        match (snapshot, current) {
            (SourceSnapshot::Missing, None) => Ok(()),
            (SourceSnapshot::Present(expected), Some(current))
                if expected.identity == current.identity && expected.bytes == current.bytes =>
            {
                Ok(())
            }
            _ => Err(ZshConfigError::ConcurrentModification),
        }
    }

    fn ensure_first_backup(
        &self,
        parent: &Path,
        snapshot: &SourceSnapshot,
    ) -> Result<(), ZshConfigError> {
        let SourceSnapshot::Present(source) = snapshot else {
            return Ok(());
        };
        let backup = backup_path(&self.rc_file);
        match fs::symlink_metadata(&backup) {
            Ok(metadata) => return validate_owned_regular(&metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(error)),
        }

        let temporary = TemporaryFile::write(parent, &source.bytes, source.identity.mode)?;
        match fs::hard_link(temporary.path(), &backup) {
            Ok(()) => sync_directory(parent).map_err(map_io),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&backup).map_err(map_io)?;
                validate_owned_regular(&metadata)
            }
            Err(error) => Err(map_io(error)),
        }
    }

    fn check_command_conflicts(
        bytes: &[u8],
        managed: Option<&Range<usize>>,
        shortcut: bool,
    ) -> Result<(), ZshConfigError> {
        let regions = unmanaged_regions(bytes, managed);
        if regions
            .iter()
            .any(|region| declares_shell_name(region, b"gschrank"))
        {
            return Err(ZshConfigError::CanonicalNameConflict);
        }
        if shortcut
            && (regions
                .iter()
                .any(|region| declares_shell_name(region, b"gsch"))
                || executable_on_path(OsStr::new("gsch")))
        {
            return Err(ZshConfigError::ShortcutNameConflict);
        }
        Ok(())
    }
}

struct ParsedManagedBlock {
    range: Range<usize>,
    configuration: StartupConfiguration,
}

fn parse_managed_block(bytes: &[u8]) -> Result<Option<ParsedManagedBlock>, ZshConfigError> {
    let starts = occurrences(bytes, ZSH_MANAGED_BLOCK_START);
    let ends = occurrences(bytes, ZSH_MANAGED_BLOCK_END);
    let managed_starts = occurrences(bytes, MANAGED_START_PREFIX);
    let managed_ends = occurrences(bytes, MANAGED_END_PREFIX);
    if managed_starts.is_empty() && managed_ends.is_empty() {
        return Ok(None);
    }
    if starts.len() != 1 || ends.len() != 1 || managed_starts.len() != 1 || managed_ends.len() != 1
    {
        return Err(ZshConfigError::MalformedManagedBlock);
    }

    let start = starts[0];
    let end = ends[0];
    if end <= start
        || !is_complete_line(bytes, start, ZSH_MANAGED_BLOCK_START.len())
        || !is_complete_line(bytes, end, ZSH_MANAGED_BLOCK_END.len())
    {
        return Err(ZshConfigError::MalformedManagedBlock);
    }
    let range_end = if bytes.get(end + ZSH_MANAGED_BLOCK_END.len()) == Some(&b'\n') {
        end + ZSH_MANAGED_BLOCK_END.len() + 1
    } else {
        end + ZSH_MANAGED_BLOCK_END.len()
    };
    let block = &bytes[start..range_end];

    let profile_value = unique_metadata(block, ZSH_STARTUP_METADATA)?;
    let profile = if profile_value == b"-" {
        None
    } else {
        let profile = std::str::from_utf8(profile_value)
            .map_err(|_| ZshConfigError::MalformedManagedBlock)?;
        Some(ProfileName::new(profile).map_err(|_| ZshConfigError::MalformedManagedBlock)?)
    };
    let shortcut = match unique_metadata(block, ZSH_SHORTCUT_METADATA)? {
        b"enabled" => true,
        b"disabled" => false,
        _ => return Err(ZshConfigError::MalformedManagedBlock),
    };

    Ok(Some(ParsedManagedBlock {
        range: start..range_end,
        configuration: StartupConfiguration::new(profile, shortcut),
    }))
}

fn unique_metadata<'bytes>(
    block: &'bytes [u8],
    prefix: &[u8],
) -> Result<&'bytes [u8], ZshConfigError> {
    let mut found = None;
    for line in block.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(prefix)
            && found.replace(value).is_some()
        {
            return Err(ZshConfigError::MalformedManagedBlock);
        }
    }
    found.ok_or(ZshConfigError::MalformedManagedBlock)
}

fn occurrences(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > bytes.len() {
        return Vec::new();
    }
    bytes
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
}

fn is_complete_line(bytes: &[u8], start: usize, length: usize) -> bool {
    (start == 0 || bytes.get(start.wrapping_sub(1)) == Some(&b'\n'))
        && matches!(bytes.get(start + length), None | Some(b'\n'))
}

fn replace_managed_block(original: &[u8], existing: Option<Range<usize>>, block: &[u8]) -> Vec<u8> {
    if let Some(range) = existing {
        let mut replacement =
            Vec::with_capacity(original.len() - (range.end - range.start) + block.len());
        replacement.extend_from_slice(&original[..range.start]);
        replacement.extend_from_slice(block);
        replacement.extend_from_slice(&original[range.end..]);
        replacement
    } else {
        let separator = usize::from(!original.is_empty() && !original.ends_with(b"\n"));
        let mut replacement = Vec::with_capacity(original.len() + separator + block.len());
        replacement.extend_from_slice(original);
        if separator == 1 {
            replacement.push(b'\n');
        }
        replacement.extend_from_slice(block);
        replacement
    }
}

fn unmanaged_regions<'bytes>(
    bytes: &'bytes [u8],
    managed: Option<&Range<usize>>,
) -> Vec<&'bytes [u8]> {
    match managed {
        Some(range) => vec![&bytes[..range.start], &bytes[range.end..]],
        None => vec![bytes],
    }
}

fn declares_shell_name(bytes: &[u8], name: &[u8]) -> bool {
    bytes.split(|byte| *byte == b'\n').any(|line| {
        line.split(|byte| *byte == b';').any(|statement| {
            let statement = trim_ascii(statement);
            if statement.is_empty() || statement[0] == b'#' {
                return false;
            }
            alias_declares(statement, name)
                || function_declares(statement, name)
                || command_declares(statement, b"autoload", name)
                || command_declares(statement, b"hash", name)
        })
    })
}

fn alias_declares(statement: &[u8], name: &[u8]) -> bool {
    let Some(rest) = command_remainder(statement, b"alias") else {
        return false;
    };
    rest.windows(name.len() + 1)
        .enumerate()
        .any(|(index, window)| {
            window.starts_with(name)
                && window[name.len()] == b'='
                && (index == 0
                    || rest[index - 1].is_ascii_whitespace()
                    || matches!(rest[index - 1], b'\'' | b'"'))
        })
}

fn function_declares(statement: &[u8], name: &[u8]) -> bool {
    if let Some(rest) = command_remainder(statement, b"function") {
        return starts_shell_word(rest, name);
    }
    let Some(rest) = statement.strip_prefix(name) else {
        return false;
    };
    let rest = trim_ascii_start(rest);
    rest.starts_with(b"()")
}

fn command_declares(statement: &[u8], command: &[u8], name: &[u8]) -> bool {
    command_remainder(statement, command)
        .is_some_and(|rest| rest.split(u8::is_ascii_whitespace).any(|word| word == name))
}

fn command_remainder<'bytes>(statement: &'bytes [u8], command: &[u8]) -> Option<&'bytes [u8]> {
    let rest = statement.strip_prefix(command)?;
    rest.first()
        .is_some_and(u8::is_ascii_whitespace)
        .then(|| trim_ascii_start(rest))
}

fn starts_shell_word(bytes: &[u8], name: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(name) else {
        return false;
    };
    rest.is_empty()
        || rest
            .first()
            .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'(' || *byte == b'{')
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    bytes = trim_ascii_start(bytes);
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn trim_ascii_start(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    bytes
}

enum SourceSnapshot {
    Missing,
    Present(OpenedStartupFile),
}

impl SourceSnapshot {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Missing => &[],
            Self::Present(file) => &file.bytes,
        }
    }

    fn mode(&self) -> Option<u32> {
        match self {
            Self::Missing => None,
            Self::Present(file) => Some(file.identity.mode),
        }
    }
}

struct OpenedStartupFile {
    bytes: Vec<u8>,
    identity: FileIdentity,
}

#[derive(Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    mode: u32,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            mode: metadata.mode() & 0o777,
        }
    }
}

fn read_regular_file(path: &Path) -> Result<Option<OpenedStartupFile>, ZshConfigError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_io(error)),
    };
    let metadata = file.metadata().map_err(map_io)?;
    validate_owned_regular(&metadata)?;
    if metadata.len() > MAX_STARTUP_FILE_BYTES as u64 {
        return Err(ZshConfigError::UnsafePath);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ZshConfigError::UnsafePath)?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take((MAX_STARTUP_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() > MAX_STARTUP_FILE_BYTES {
        return Err(ZshConfigError::UnsafePath);
    }
    Ok(Some(OpenedStartupFile {
        bytes,
        identity: FileIdentity::from_metadata(&metadata),
    }))
}

fn validate_owned_regular(metadata: &Metadata) -> Result<(), ZshConfigError> {
    if !metadata.file_type().is_file() || metadata.uid() != system::effective_user_id() {
        Err(ZshConfigError::UnsafePath)
    } else {
        Ok(())
    }
}

fn path_exists_safely(path: &Path) -> Result<bool, ZshConfigError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(map_io(error)),
    }
}

fn compiled_path(rc_file: &Path) -> PathBuf {
    let mut name = rc_file.file_name().unwrap_or_default().to_os_string();
    name.push(".zwc");
    rc_file.with_file_name(name)
}

fn backup_path(rc_file: &Path) -> PathBuf {
    let mut name = rc_file.file_name().unwrap_or_default().to_os_string();
    name.push(".gschrank-backup");
    rc_file.with_file_name(name)
}

fn executable_on_path(name: &OsStr) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| {
        if !directory.is_absolute() {
            return false;
        }
        fs::metadata(directory.join(name)).is_ok_and(|metadata| {
            metadata.file_type().is_file() && metadata.permissions().mode() & 0o111 != 0
        })
    })
}

struct TemporaryFile {
    path: PathBuf,
}

impl TemporaryFile {
    fn write(parent: &Path, bytes: &[u8], mode: u32) -> Result<Self, ZshConfigError> {
        for _ in 0..TEMP_ATTEMPTS {
            let path = parent.join(temporary_name()?);
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            let mut file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(map_io(error)),
            };
            let result = (|| {
                validate_owned_regular(&file.metadata().map_err(map_io)?)?;
                file.set_permissions(fs::Permissions::from_mode(mode))
                    .map_err(map_io)?;
                file.write_all(bytes).map_err(map_io)?;
                file.flush().map_err(map_io)?;
                system::full_sync(&file).map_err(map_io)
            })();
            if let Err(error) = result {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
            return Ok(Self { path });
        }
        Err(ZshConfigError::IoFailure)
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

fn temporary_name() -> Result<OsString, ZshConfigError> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| ZshConfigError::IoFailure)?;
    let mut name = String::from(".gschrank-zshrc-");
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name.push_str(".tmp");
    Ok(OsString::from(name))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ZshConfigError {
    UnsafePath,
    ShadowedByCompiledFile,
    MalformedManagedBlock,
    CanonicalNameConflict,
    ShortcutNameConflict,
    ConcurrentModification,
    PermissionDenied,
    IoFailure,
    OutcomeIndeterminate,
}

impl ZshConfigError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::UnsafePath | Self::ShadowedByCompiledFile | Self::PermissionDenied => 13,
            Self::MalformedManagedBlock
            | Self::CanonicalNameConflict
            | Self::ShortcutNameConflict
            | Self::ConcurrentModification => 14,
            Self::OutcomeIndeterminate => 15,
            Self::IoFailure => 1,
        }
    }
}

impl fmt::Display for ZshConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "the Zsh startup path is unsafe",
            Self::ShadowedByCompiledFile => {
                "a compiled Zsh startup file could shadow this change; remove or rebuild it first"
            }
            Self::MalformedManagedBlock => {
                "the managed Zsh block is malformed or duplicated; no change was made"
            }
            Self::CanonicalNameConflict => {
                "the 'gschrank' shell name is already defined outside the managed block"
            }
            Self::ShortcutNameConflict => "the optional 'gsch' shell name is already in use",
            Self::ConcurrentModification => {
                "the Zsh startup file changed during configuration; no replacement was made"
            }
            Self::PermissionDenied => "permission to edit the Zsh startup file was denied",
            Self::IoFailure => "the Zsh startup file could not be updated",
            Self::OutcomeIndeterminate => {
                "the Zsh startup update outcome is indeterminate; inspect it before retrying"
            }
        })
    }
}

impl Error for ZshConfigError {}

fn map_io(error: io::Error) -> ZshConfigError {
    let kind = error.kind();
    let native = error.raw_os_error();
    drop(error);
    match (kind, native) {
        (_, Some(libc::ELOOP)) => ZshConfigError::UnsafePath,
        (io::ErrorKind::PermissionDenied, _) => ZshConfigError::PermissionDenied,
        _ => ZshConfigError::IoFailure,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::shell::ZshEmitter;

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "gschrank-zsh-config-test-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }

        fn rc_file(&self) -> PathBuf {
            self.0.join(".zshrc")
        }

        fn editor(&self) -> ZshConfigEditor {
            ZshConfigEditor::at_path(self.rc_file())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn configuration(profile: Option<&str>, shortcut: bool) -> StartupConfiguration {
        StartupConfiguration::new(
            profile.map(|name| ProfileName::new(name).unwrap()),
            shortcut,
        )
    }

    fn block(profile: Option<&str>, shortcut: bool) -> ZshManagedBlock {
        ZshEmitter::emit_managed_block(configuration(profile, shortcut))
    }

    #[test]
    fn installs_updates_and_turns_startup_off_without_rewriting_user_content() {
        let test = TestDirectory::new();
        let rc_file = test.rc_file();
        let original = b"# existing user configuration\nexport USER_SETTING=kept\n";
        fs::write(&rc_file, original).unwrap();
        fs::set_permissions(&rc_file, fs::Permissions::from_mode(0o640)).unwrap();
        let editor = test.editor();

        assert_eq!(
            editor.configure(&block(Some("work"), false)).unwrap(),
            ShellConfigEdit::Installed
        );
        let installed = fs::read(&rc_file).unwrap();
        assert!(installed.starts_with(original));
        assert_eq!(occurrences(&installed, ZSH_MANAGED_BLOCK_START).len(), 1);
        assert_eq!(fs::metadata(&rc_file).unwrap().mode() & 0o777, 0o640);
        assert_eq!(fs::read(backup_path(&rc_file)).unwrap(), original);
        assert_eq!(
            fs::metadata(backup_path(&rc_file)).unwrap().mode() & 0o777,
            0o640
        );
        assert_eq!(
            editor.inspect().unwrap(),
            ShellIntegrationState::Installed(configuration(Some("work"), false))
        );

        assert_eq!(
            editor.configure(&block(Some("work"), false)).unwrap(),
            ShellConfigEdit::Unchanged
        );
        assert_eq!(fs::read(&rc_file).unwrap(), installed);

        assert_eq!(
            editor.configure(&block(Some("personal"), false)).unwrap(),
            ShellConfigEdit::Updated
        );
        assert_eq!(fs::read(backup_path(&rc_file)).unwrap(), original);
        assert_eq!(
            editor.inspect().unwrap(),
            ShellIntegrationState::Installed(configuration(Some("personal"), false))
        );

        assert_eq!(
            editor.configure(&block(None, false)).unwrap(),
            ShellConfigEdit::Updated
        );
        let final_bytes = fs::read(&rc_file).unwrap();
        assert!(final_bytes.starts_with(original));
        assert_eq!(occurrences(&final_bytes, ZSH_MANAGED_BLOCK_START).len(), 1);
        assert_eq!(
            editor.inspect().unwrap(),
            ShellIntegrationState::Installed(configuration(None, false))
        );
    }

    #[test]
    fn creates_a_missing_startup_file_restrictively_without_a_backup() {
        let test = TestDirectory::new();
        let editor = test.editor();
        assert_eq!(editor.inspect().unwrap(), ShellIntegrationState::Absent);

        assert_eq!(
            editor.configure(&block(None, false)).unwrap(),
            ShellConfigEdit::Installed
        );
        assert_eq!(fs::metadata(test.rc_file()).unwrap().mode() & 0o777, 0o600);
        assert!(!backup_path(&test.rc_file()).exists());
    }

    #[test]
    fn rejects_symlinks_compiled_shadow_files_and_malformed_markers() {
        let symlink_test = TestDirectory::new();
        let target = symlink_test.0.join("target");
        fs::write(&target, b"untouched\n").unwrap();
        symlink(&target, symlink_test.rc_file()).unwrap();
        assert_eq!(
            symlink_test.editor().inspect().unwrap_err(),
            ZshConfigError::UnsafePath
        );
        assert_eq!(fs::read(&target).unwrap(), b"untouched\n");

        let compiled_test = TestDirectory::new();
        fs::write(compiled_path(&compiled_test.rc_file()), b"compiled").unwrap();
        assert_eq!(
            compiled_test.editor().inspect().unwrap_err(),
            ZshConfigError::ShadowedByCompiledFile
        );

        for malformed in [
            format!(
                "{}\n",
                std::str::from_utf8(ZSH_MANAGED_BLOCK_START).unwrap()
            ),
            format!(
                "{}\n{}\n{}\n",
                std::str::from_utf8(ZSH_MANAGED_BLOCK_START).unwrap(),
                std::str::from_utf8(ZSH_MANAGED_BLOCK_START).unwrap(),
                std::str::from_utf8(ZSH_MANAGED_BLOCK_END).unwrap()
            ),
            format!(
                "prefix {} suffix\n{}\n",
                std::str::from_utf8(ZSH_MANAGED_BLOCK_START).unwrap(),
                std::str::from_utf8(ZSH_MANAGED_BLOCK_END).unwrap()
            ),
            "# >>> gschrank initialize v2 >>>\n# <<< gschrank initialize v2 <<<\n".to_owned(),
        ] {
            let test = TestDirectory::new();
            fs::write(test.rc_file(), malformed).unwrap();
            assert_eq!(
                test.editor().inspect().unwrap_err(),
                ZshConfigError::MalformedManagedBlock
            );
        }
    }

    #[test]
    fn detects_canonical_and_optional_shortcut_declarations_before_writing() {
        let canonical = TestDirectory::new();
        let canonical_bytes = b"function gschrank { print unrelated }\n";
        fs::write(canonical.rc_file(), canonical_bytes).unwrap();
        assert_eq!(
            canonical
                .editor()
                .configure(&block(Some("work"), false))
                .unwrap_err(),
            ZshConfigError::CanonicalNameConflict
        );
        assert_eq!(fs::read(canonical.rc_file()).unwrap(), canonical_bytes);

        let shortcut = TestDirectory::new();
        let shortcut_bytes = b"alias gsch='another command'\n";
        fs::write(shortcut.rc_file(), shortcut_bytes).unwrap();
        assert_eq!(
            shortcut
                .editor()
                .configure(&block(Some("work"), true))
                .unwrap_err(),
            ZshConfigError::ShortcutNameConflict
        );
        assert_eq!(
            shortcut
                .editor()
                .configure(&block(Some("work"), false))
                .unwrap(),
            ShellConfigEdit::Installed
        );
        assert!(
            fs::read(shortcut.rc_file())
                .unwrap()
                .starts_with(shortcut_bytes)
        );
    }

    #[test]
    fn a_concurrent_change_is_never_replaced_or_backed_up_as_authoritative() {
        let test = TestDirectory::new();
        fs::write(test.rc_file(), b"before\n").unwrap();
        let editor = test.editor();

        let error = editor
            .configure_with(&block(Some("work"), false), || {
                fs::write(test.rc_file(), b"concurrent user edit\n").unwrap();
            })
            .unwrap_err();
        assert_eq!(error, ZshConfigError::ConcurrentModification);
        assert_eq!(fs::read(test.rc_file()).unwrap(), b"concurrent user edit\n");
        assert!(!backup_path(&test.rc_file()).exists());
        assert!(fs::read_dir(&test.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn refuses_an_unsafe_existing_backup_instead_of_overwriting_it() {
        let test = TestDirectory::new();
        fs::write(test.rc_file(), b"original\n").unwrap();
        let outside = test.0.join("outside");
        fs::write(&outside, b"do not overwrite\n").unwrap();
        symlink(&outside, backup_path(&test.rc_file())).unwrap();

        assert_eq!(
            test.editor()
                .configure(&block(Some("work"), false))
                .unwrap_err(),
            ZshConfigError::UnsafePath
        );
        assert_eq!(fs::read(test.rc_file()).unwrap(), b"original\n");
        assert_eq!(fs::read(outside).unwrap(), b"do not overwrite\n");
    }
}
