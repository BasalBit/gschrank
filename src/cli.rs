#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    io::{IsTerminal, Write},
    path::PathBuf,
    process::ExitCode,
};

use crate::{
    DomainError, EnvironmentName, Mutation, ProfileName,
    config_command::{
        ConfigJourneyOutcome, ConfigPrompter, TerminalConfigPrompter, run_config_journey,
    },
    confirmation::TerminalTypedConfirmer,
    import_command::{ImportCommandError, ImportOptions, ImportOutcome, execute_import},
    init::{InitOutcome, Initializer},
    key_provider::InteractionPolicy,
    profiles::{
        BackupReceipt, ImportOperationError, ProfileInspection, ProfileOperationError,
        ProfileOperations, VaultInspection, VaultReadiness,
    },
    purge::{FullPurgeError, FullPurgeOperations, FullPurgePreparationError, FullPurgeReceipt},
    rebuild::{RebuildOperations, RebuildReceipt},
    recovery::{RecoveryList, RecoveryOperationError, RecoveryOperations, RecoveryOverview},
    recovery_purge::{RecoveryPurgeOperations, RecoveryPurgeReceipt},
    reset::{ResetError, ResetOperations, ResetPreparationError, ResetReceipt},
    restore::{RestoreOperations, RestoreReceipt},
    secret_input::{SecretInputMode, read_secret},
    set_command::execute_set,
    shell::{ShellEmitter, ZshEmitter},
    shell_config::{ShellConfigEdit, ShellIntegrationState, StartupConfiguration},
    shell_transition::{
        ACTIVE_PROFILE_NAME, ENV_PROTOCOL_NAME, MANAGED_KEYS_NAME, ManagedState, ManagedStateError,
        OperationContext, ShellTransition,
    },
    vault_store::RecoveryBundleId,
};

#[cfg(target_os = "macos")]
use crate::platform::macos::{
    EncryptedBackupWriter, EncryptedRestoreSource, LocalVaultStore, MacOsKeychainProvider,
    MacOsPathError, MacOsPaths, PreferenceError, ShellPreferenceStore, ShellPreferences,
    ShortcutDiagnostic, ZshConfigEditor, ZshConfigError, ZshDiagnostic,
};

const HELP: &str = concat!(
    "gschrank ",
    env!("CARGO_PKG_VERSION"),
    "

Encrypted environment profiles for your shell.

Usage:
  gschrank config [--rc-file <absolute-path>]
  gschrank init
  gschrank status
  gschrank doctor
  gschrank backup <absolute-destination>
  gschrank restore <absolute-source>
  gschrank rebuild
  gschrank reset
  gschrank purge
  gschrank recovery list
  gschrank recovery restore <bundle-id>
  gschrank recovery purge <bundle-id>
  gschrank import dotenv <profile> [--dry-run] [--replace-existing]
  gschrank profile create <profile>
  gschrank profile rename <old> <new>
  gschrank profile delete <profile>
  gschrank profile list
  gschrank profile inspect <profile>
  gschrank set <profile> <variable> [--stdin]
  gschrank remove <profile> <variable>
  gschrank startup set <profile>
  gschrank startup off
  gschrank shell uninstall
  gschrank load <profile>
  gschrank reload
  gschrank unload
  gschrank --help
  gschrank --version

Commands:
  config     Guided vault, profile, secret, and Zsh startup setup
  init       Create an empty encrypted vault, or validate the existing vault
  status     Show authenticated names-only vault and current-shell state
  doctor     Check vault and shell readiness without showing decrypted names
  backup     Create a Keychain-bound encrypted vault backup without overwriting
  restore    Authenticate and restore a Keychain-bound encrypted vault backup
  rebuild    Re-encrypt every profile under a new vault identity and master key
  reset      Preserve current state and create a new independently keyed empty vault
  purge      Permanently remove local vault state, integration, and authenticated keys
  recovery   List, validate, restore, or purge durable internal recovery bundles
  import     Add a strict stdin-only dotenv document to an existing profile
  profile    Create, rename, delete, list, or inspect profiles
  set        Create or update a variable using hidden or explicit stdin input
  remove     Remove a variable from a profile
  startup    Select a profile for new Zsh shells, or turn automatic loading off
  shell      Manage the installed current-shell integration
  load       Load a profile through the installed current-shell wrapper
  reload     Reload the active profile through the current-shell wrapper
  unload     Clear the active profile through the current-shell wrapper

Only macOS and Zsh are supported in this development milestone. Current-shell
commands require the managed Zsh function; the executable cannot mutate its
parent shell."
);

enum Command {
    Help,
    Version,
    Config {
        rc_file: Option<PathBuf>,
    },
    Init,
    Status,
    Doctor,
    Backup(PathBuf),
    Restore(PathBuf),
    Rebuild,
    Reset {
        shell_wrapper: bool,
    },
    Purge {
        shell_wrapper: bool,
    },
    ShellUninstall {
        shell_wrapper: bool,
    },
    RecoveryList,
    RecoveryRestore(RecoveryBundleId),
    RecoveryPurge(RecoveryBundleId),
    Import {
        profile: ProfileName,
        options: ImportOptions,
    },
    Profile(ProfileCommand),
    Set {
        profile: ProfileName,
        variable: EnvironmentName,
        input: SecretInputMode,
    },
    Remove {
        profile: ProfileName,
        variable: EnvironmentName,
    },
    Startup(StartupCommand),
    ShellParent(ShellParentCommand),
    ShellInit {
        shortcut: bool,
    },
    EmitZsh {
        context: OperationContext,
        operation: EmitOperation,
    },
}

enum ShellParentCommand {
    Load(ProfileName),
    StartupLoad(ProfileName),
    Reload,
    Unload,
}

enum StartupCommand {
    Set(ProfileName),
    Off,
}

enum EmitOperation {
    Load(ProfileName),
    Reload,
    Unload,
}

enum ProfileCommand {
    Create(ProfileName),
    Rename { old: ProfileName, new: ProfileName },
    Delete(ProfileName),
    List,
    Inspect(ProfileName),
}

#[cfg(target_os = "macos")]
struct ResolvedZshConfig {
    editor: ZshConfigEditor,
    saved: Option<ShellPreferences>,
    preferences: ShellPreferenceStore,
}

#[cfg(target_os = "macos")]
impl ResolvedZshConfig {
    fn remember(&self, shortcut: bool) -> Result<(), ShellConfigurationError> {
        let preferences = ShellPreferences::new(self.editor.path().to_owned(), shortcut)?;
        self.preferences.write(&preferences)?;
        Ok(())
    }

    fn shortcut_default(&self) -> bool {
        self.saved.as_ref().is_none_or(ShellPreferences::shortcut)
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShellConfigurationError {
    Preferences(PreferenceError),
    Editor(ZshConfigError),
    DifferentRcFile,
}

#[cfg(target_os = "macos")]
impl ShellConfigurationError {
    const fn exit_code(self) -> u8 {
        match self {
            Self::Preferences(error) => error.exit_code(),
            Self::Editor(error) => error.exit_code(),
            Self::DifferentRcFile => 14,
        }
    }
}

#[cfg(target_os = "macos")]
impl std::fmt::Display for ShellConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preferences(error) => error.fmt(formatter),
            Self::Editor(error) => error.fmt(formatter),
            Self::DifferentRcFile => formatter.write_str(
                "a different Zsh startup file is already selected; changing rc files safely is not available yet",
            ),
        }
    }
}

#[cfg(target_os = "macos")]
impl From<PreferenceError> for ShellConfigurationError {
    fn from(error: PreferenceError) -> Self {
        Self::Preferences(error)
    }
}

#[cfg(target_os = "macos")]
impl From<ZshConfigError> for ShellConfigurationError {
    fn from(error: ZshConfigError) -> Self {
        Self::Editor(error)
    }
}

enum ProfileSuccess {
    Created(ProfileName),
    Renamed {
        old: ProfileName,
        new: ProfileName,
    },
    Deleted(ProfileName),
    Listed(Vec<ProfileName>),
    Inspected(ProfileInspection),
    Set {
        profile: ProfileName,
        variable: EnvironmentName,
        mutation: Mutation,
    },
    Removed {
        profile: ProfileName,
        variable: EnvironmentName,
    },
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
enum ProfileCommandError {
    Profile(ProfileOperationError),
    ShellConfig(ShellConfigurationError),
    ConfiguredStartupProfile,
    RenameRollbackFailed,
}

#[cfg(target_os = "macos")]
impl ProfileCommandError {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Profile(error) => error.exit_code(),
            Self::ShellConfig(error) => error.exit_code(),
            Self::ConfiguredStartupProfile => 14,
            Self::RenameRollbackFailed => 15,
        }
    }
}

#[cfg(target_os = "macos")]
impl std::fmt::Display for ProfileCommandError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Profile(error) => error.fmt(formatter),
            Self::ShellConfig(error) => error.fmt(formatter),
            Self::ConfiguredStartupProfile => formatter.write_str(
                "the profile is configured for new shells; select another startup profile or run 'gschrank startup off' first",
            ),
            Self::RenameRollbackFailed => formatter.write_str(
                "profile rename failed and the startup configuration could not be restored; inspect both states before retrying",
            ),
        }
    }
}

#[cfg(target_os = "macos")]
impl From<ProfileOperationError> for ProfileCommandError {
    fn from(error: ProfileOperationError) -> Self {
        Self::Profile(error)
    }
}

#[cfg(target_os = "macos")]
impl From<ZshConfigError> for ProfileCommandError {
    fn from(error: ZshConfigError) -> Self {
        Self::ShellConfig(error.into())
    }
}

#[cfg(target_os = "macos")]
impl From<ShellConfigurationError> for ProfileCommandError {
    fn from(error: ShellConfigurationError) -> Self {
        Self::ShellConfig(error)
    }
}

#[cfg(target_os = "macos")]
struct StartupSuccess {
    edit: ShellConfigEdit,
    configuration: StartupConfiguration,
    shortcut_conflict: bool,
}

#[cfg(target_os = "macos")]
struct StatusReport {
    vault: Result<VaultInspection, ProfileOperationError>,
    recovery: Result<RecoveryOverview, RecoveryOperationError>,
    shell: Result<ZshDiagnostic, ShellConfigurationError>,
    current_shell: Result<ManagedState, ManagedStateError>,
}

#[cfg(target_os = "macos")]
impl StatusReport {
    fn exit_code(&self) -> u8 {
        if self.recovery.is_ok_and(|overview| {
            overview.full_purge_pending
                || overview.purge_pending_count > 0
                || overview.rebuild_pending
                || (overview.initialization_pending
                    && matches!(self.vault, Err(ProfileOperationError::NotInitialized)))
        }) {
            14
        } else if let Err(error) = self.vault {
            error.exit_code()
        } else if let Err(error) = self.recovery {
            error.exit_code()
        } else if self
            .recovery
            .is_ok_and(|overview| overview.initialization_pending || overview.rebuild_pending)
        {
            14
        } else if let Err(error) = self.shell {
            error.exit_code()
        } else if self.current_shell.is_err() {
            14
        } else {
            0
        }
    }
}

#[cfg(target_os = "macos")]
struct DoctorReport {
    vault: Result<VaultReadiness, ProfileOperationError>,
    recovery: Result<RecoveryOverview, RecoveryOperationError>,
    shell: Result<ZshDiagnostic, ShellConfigurationError>,
    current_shell: Result<ManagedState, ManagedStateError>,
}

#[cfg(target_os = "macos")]
impl DoctorReport {
    fn exit_code(&self) -> u8 {
        if self.recovery.is_ok_and(|overview| {
            overview.full_purge_pending
                || overview.purge_pending_count > 0
                || overview.rebuild_pending
                || (overview.initialization_pending
                    && matches!(self.vault, Err(ProfileOperationError::NotInitialized)))
        }) {
            return 14;
        }
        if let Err(error) = self.vault {
            return error.exit_code();
        }
        if let Err(error) = self.recovery {
            return error.exit_code();
        }
        if self
            .recovery
            .is_ok_and(|overview| overview.initialization_pending || overview.rebuild_pending)
        {
            return 14;
        }
        let shell = match &self.shell {
            Ok(shell) => shell,
            Err(error) => return error.exit_code(),
        };
        if self.current_shell.is_err()
            || shell.integration == ShellIntegrationState::Absent
            || shell.canonical_conflict
        {
            14
        } else {
            0
        }
    }
}

enum ParseError {
    InvalidGrammar,
    InvalidName(DomainError),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGrammar => formatter.write_str("invalid command or arguments"),
            Self::InvalidName(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

/// Runs the current Gschrank command surface.
pub fn run_cli(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    match parse(&arguments) {
        Ok(Command::Help) => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Ok(Command::Version) => {
            println!("gschrank {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Command::Config { rc_file }) => run_config(rc_file),
        Ok(Command::Init) => run_init(),
        Ok(Command::Status) => run_status(),
        Ok(Command::Doctor) => run_doctor(),
        Ok(Command::Backup(destination)) => run_backup(destination),
        Ok(Command::Restore(source)) => run_restore(source),
        Ok(Command::Rebuild) => run_rebuild(),
        Ok(Command::Reset { shell_wrapper }) => run_reset(shell_wrapper),
        Ok(Command::Purge { shell_wrapper }) => run_full_purge(shell_wrapper),
        Ok(Command::ShellUninstall { shell_wrapper }) => run_shell_uninstall(shell_wrapper),
        Ok(Command::RecoveryList) => run_recovery_list(),
        Ok(Command::RecoveryRestore(bundle_id)) => run_recovery_restore(bundle_id),
        Ok(Command::RecoveryPurge(bundle_id)) => run_recovery_purge(bundle_id),
        Ok(Command::Import { profile, options }) => run_import(&profile, options),
        Ok(Command::Profile(command)) => run_profile(command),
        Ok(Command::Set {
            profile,
            variable,
            input,
        }) => run_set(&profile, variable, input),
        Ok(Command::Remove { profile, variable }) => run_remove(&profile, &variable),
        Ok(Command::Startup(command)) => run_startup(command),
        Ok(Command::ShellParent(command)) => run_shell_parent(command),
        Ok(Command::ShellInit { shortcut }) => run_shell_init(shortcut),
        Ok(Command::EmitZsh { context, operation }) => run_emit_zsh(context, operation),
        Err(error) => {
            eprintln!("gschrank: {error}\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}

fn parse(arguments: &[OsString]) -> Result<Command, ParseError> {
    match arguments {
        [] => Ok(Command::Help),
        [argument] if argument == "--help" || argument == "-h" => Ok(Command::Help),
        [argument] if argument == "--version" || argument == "-V" => Ok(Command::Version),
        [config] if config == "config" => Ok(Command::Config { rc_file: None }),
        [config, rc_file, path] if config == "config" && rc_file == "--rc-file" => {
            Ok(Command::Config {
                rc_file: Some(PathBuf::from(path)),
            })
        }
        [argument] if argument == "init" => Ok(Command::Init),
        [argument] if argument == "status" => Ok(Command::Status),
        [argument] if argument == "doctor" => Ok(Command::Doctor),
        [backup, destination] if backup == "backup" => {
            Ok(Command::Backup(PathBuf::from(destination)))
        }
        [restore, source] if restore == "restore" => Ok(Command::Restore(PathBuf::from(source))),
        [rebuild] if rebuild == "rebuild" => Ok(Command::Rebuild),
        [reset] if reset == "reset" => Ok(Command::Reset {
            shell_wrapper: false,
        }),
        [purge] if purge == "purge" => Ok(Command::Purge {
            shell_wrapper: false,
        }),
        [recovery, list] if recovery == "recovery" && list == "list" => Ok(Command::RecoveryList),
        [recovery, restore, bundle_id] if recovery == "recovery" && restore == "restore" => {
            let bundle_id = bundle_id.to_str().ok_or(ParseError::InvalidGrammar)?;
            Ok(Command::RecoveryRestore(
                RecoveryBundleId::from_hex(bundle_id).ok_or(ParseError::InvalidGrammar)?,
            ))
        }
        [recovery, purge, bundle_id] if recovery == "recovery" && purge == "purge" => {
            let bundle_id = bundle_id.to_str().ok_or(ParseError::InvalidGrammar)?;
            Ok(Command::RecoveryPurge(
                RecoveryBundleId::from_hex(bundle_id).ok_or(ParseError::InvalidGrammar)?,
            ))
        }
        [import, dotenv, arguments @ ..] if import == "import" && dotenv == "dotenv" => {
            parse_import(arguments)
        }
        [profile, list] if profile == "profile" && list == "list" => {
            Ok(Command::Profile(ProfileCommand::List))
        }
        [profile, create, name] if profile == "profile" && create == "create" => Ok(
            Command::Profile(ProfileCommand::Create(parse_profile_name(name)?)),
        ),
        [profile, delete, name] if profile == "profile" && delete == "delete" => Ok(
            Command::Profile(ProfileCommand::Delete(parse_profile_name(name)?)),
        ),
        [profile, inspect, name] if profile == "profile" && inspect == "inspect" => Ok(
            Command::Profile(ProfileCommand::Inspect(parse_profile_name(name)?)),
        ),
        [profile, rename, old, new] if profile == "profile" && rename == "rename" => {
            Ok(Command::Profile(ProfileCommand::Rename {
                old: parse_profile_name(old)?,
                new: parse_profile_name(new)?,
            }))
        }
        [set, profile, variable] if set == "set" => Ok(Command::Set {
            profile: parse_profile_name(profile)?,
            variable: parse_environment_name(variable)?,
            input: SecretInputMode::HiddenTerminal,
        }),
        [set, profile, variable, stdin] if set == "set" && stdin == "--stdin" => Ok(Command::Set {
            profile: parse_profile_name(profile)?,
            variable: parse_environment_name(variable)?,
            input: SecretInputMode::Stdin,
        }),
        [remove, profile, variable] if remove == "remove" => Ok(Command::Remove {
            profile: parse_profile_name(profile)?,
            variable: parse_environment_name(variable)?,
        }),
        [startup, set, profile] if startup == "startup" && set == "set" => Ok(Command::Startup(
            StartupCommand::Set(parse_profile_name(profile)?),
        )),
        [startup, off] if startup == "startup" && off == "off" => {
            Ok(Command::Startup(StartupCommand::Off))
        }
        [shell, uninstall] if shell == "shell" && uninstall == "uninstall" => {
            Ok(Command::ShellUninstall {
                shell_wrapper: false,
            })
        }
        [load, profile] if load == "load" => Ok(Command::ShellParent(ShellParentCommand::Load(
            parse_profile_name(profile)?,
        ))),
        [load, startup, separator, profile]
            if load == "load" && startup == "--startup" && separator == "--" =>
        {
            Ok(Command::ShellParent(ShellParentCommand::StartupLoad(
                parse_profile_name(profile)?,
            )))
        }
        [reload] if reload == "reload" => Ok(Command::ShellParent(ShellParentCommand::Reload)),
        [unload] if unload == "unload" => Ok(Command::ShellParent(ShellParentCommand::Unload)),
        _ => parse_private(arguments),
    }
}

fn parse_import(arguments: &[OsString]) -> Result<Command, ParseError> {
    let Some((profile, flags)) = arguments.split_first() else {
        return Err(ParseError::InvalidGrammar);
    };
    let mut dry_run = false;
    let mut replace_existing = false;
    for flag in flags {
        if flag == "--dry-run" && !dry_run {
            dry_run = true;
        } else if flag == "--replace-existing" && !replace_existing {
            replace_existing = true;
        } else {
            return Err(ParseError::InvalidGrammar);
        }
    }
    Ok(Command::Import {
        profile: parse_profile_name(profile)?,
        options: ImportOptions {
            dry_run,
            replace_existing,
        },
    })
}

fn parse_private(arguments: &[OsString]) -> Result<Command, ParseError> {
    match arguments {
        [reset] if reset == "__reset-from-zsh" => Ok(Command::Reset {
            shell_wrapper: true,
        }),
        [purge] if purge == "__purge-from-zsh" => Ok(Command::Purge {
            shell_wrapper: true,
        }),
        [uninstall] if uninstall == "__shell-uninstall-from-zsh" => Ok(Command::ShellUninstall {
            shell_wrapper: true,
        }),
        [shell_init, shell, protocol]
            if shell_init == "__shell-init" && shell == "zsh" && protocol == "1" =>
        {
            Ok(Command::ShellInit { shortcut: false })
        }
        [shell_init, shell, protocol, shortcut]
            if shell_init == "__shell-init"
                && shell == "zsh"
                && protocol == "1"
                && shortcut == "--shortcut" =>
        {
            Ok(Command::ShellInit { shortcut: true })
        }
        [emit, protocol, context, load, separator, profile]
            if emit == "__emit-zsh" && protocol == "1" && load == "load" && separator == "--" =>
        {
            Ok(Command::EmitZsh {
                context: parse_operation_context(context)?,
                operation: EmitOperation::Load(parse_profile_name(profile)?),
            })
        }
        [emit, protocol, context, reload]
            if emit == "__emit-zsh" && protocol == "1" && reload == "reload" =>
        {
            let context = parse_operation_context(context)?;
            if context != OperationContext::Explicit {
                return Err(ParseError::InvalidGrammar);
            }
            Ok(Command::EmitZsh {
                context,
                operation: EmitOperation::Reload,
            })
        }
        [emit, protocol, context, unload]
            if emit == "__emit-zsh" && protocol == "1" && unload == "unload" =>
        {
            let context = parse_operation_context(context)?;
            if context != OperationContext::Explicit {
                return Err(ParseError::InvalidGrammar);
            }
            Ok(Command::EmitZsh {
                context,
                operation: EmitOperation::Unload,
            })
        }
        _ => Err(ParseError::InvalidGrammar),
    }
}

fn parse_operation_context(argument: &OsString) -> Result<OperationContext, ParseError> {
    if argument == "explicit" {
        Ok(OperationContext::Explicit)
    } else if argument == "startup" {
        Ok(OperationContext::AutomaticStartup)
    } else {
        Err(ParseError::InvalidGrammar)
    }
}

fn parse_profile_name(argument: &OsString) -> Result<ProfileName, ParseError> {
    let name = argument.to_str().ok_or(ParseError::InvalidGrammar)?;
    ProfileName::new(name).map_err(ParseError::InvalidName)
}

fn parse_environment_name(argument: &OsString) -> Result<EnvironmentName, ParseError> {
    let name = argument.to_str().ok_or(ParseError::InvalidGrammar)?;
    EnvironmentName::new(name).map_err(ParseError::InvalidName)
}

fn interaction_policy() -> InteractionPolicy {
    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        InteractionPolicy::AllowPrompt
    } else {
        InteractionPolicy::FailFast
    }
}

#[cfg(target_os = "macos")]
fn resolve_zsh_config(
    paths: &MacOsPaths,
    explicit_rc_file: Option<PathBuf>,
) -> Result<ResolvedZshConfig, ShellConfigurationError> {
    let preferences = ShellPreferenceStore::new(paths.data_directory().to_owned());
    let saved = preferences.read()?;
    let editor = match explicit_rc_file {
        Some(path) => {
            // Reuse the persisted preference validator before any vault or rc
            // state is changed.
            let candidate = ShellPreferences::new(path.clone(), false)?;
            if saved
                .as_ref()
                .is_some_and(|saved| saved.rc_file() != candidate.rc_file())
            {
                return Err(ShellConfigurationError::DifferentRcFile);
            }
            ZshConfigEditor::at_path(path)
        }
        None => saved.as_ref().map_or_else(
            || ZshConfigEditor::discover().map_err(ShellConfigurationError::from),
            |saved| Ok(ZshConfigEditor::at_path(saved.rc_file().to_owned())),
        )?,
    };
    Ok(ResolvedZshConfig {
        editor,
        saved,
        preferences,
    })
}

#[cfg(target_os = "macos")]
fn run_config(explicit_rc_file: Option<PathBuf>) -> ExitCode {
    let mut prompts = match TerminalConfigPrompter::new() {
        Ok(prompts) => prompts,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(error.exit_code());
        }
    };
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let resolved = match resolve_zsh_config(&paths, explicit_rc_file) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(error.exit_code());
        }
    };
    let integration = match resolved.editor.inspect() {
        Ok(integration) => integration,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(error.exit_code());
        }
    };
    let shortcut_default = integration.configuration().map_or_else(
        || resolved.shortcut_default(),
        StartupConfiguration::shortcut,
    );

    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let initializer = Initializer::new(&keys, &store);
    let operations = ProfileOperations::new(&keys, &store);
    let interaction = InteractionPolicy::AllowPrompt;
    let selection = match run_config_journey(
        &initializer,
        &operations,
        &mut prompts,
        interaction,
        shortcut_default,
    ) {
        Ok(ConfigJourneyOutcome::Cancelled) => return ExitCode::SUCCESS,
        Ok(ConfigJourneyOutcome::Selected(selection)) => selection,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(error.exit_code());
        }
    };

    let requested = StartupConfiguration::new(
        selection.startup.then(|| selection.profile.clone()),
        selection.shortcut,
    );
    if let Err(error) = prompts.announce("Installing the managed Zsh startup integration...") {
        eprintln!("gschrank: {error}");
        return ExitCode::from(error.exit_code());
    }
    let success = match configure_startup(&resolved.editor, requested) {
        Ok(success) => success,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(error.exit_code());
        }
    };
    if let Err(error) = resolved.remember(success.configuration.shortcut()) {
        eprintln!(
            "gschrank: the Zsh startup file was updated, but its selected path could not be saved: {error}"
        );
        return ExitCode::from(error.exit_code());
    }
    if success.shortcut_conflict {
        eprintln!(
            "gschrank: the optional 'gsch' name is already in use; installed only the canonical 'gschrank' function"
        );
    }
    print!("{}", render_startup_success(&success));
    println!(
        "Configuration complete for profile '{}'; {} variable(s) changed{}.",
        selection.profile.as_str(),
        selection.variables_changed,
        if selection.created_vault {
            " in the newly initialized vault"
        } else {
            ""
        }
    );
    ExitCode::SUCCESS
}

fn render_profile_success(success: ProfileSuccess) -> String {
    let mut output = String::new();
    match success {
        ProfileSuccess::Created(profile) => {
            output.push_str("Created profile '");
            output.push_str(profile.as_str());
            output.push_str("'.\n");
        }
        ProfileSuccess::Renamed { old, new } => {
            output.push_str("Renamed profile '");
            output.push_str(old.as_str());
            output.push_str("' to '");
            output.push_str(new.as_str());
            output.push_str("'.\n");
        }
        ProfileSuccess::Deleted(profile) => {
            output.push_str("Deleted profile '");
            output.push_str(profile.as_str());
            output.push_str("'.\n");
        }
        ProfileSuccess::Listed(profiles) => {
            for profile in profiles {
                output.push_str(profile.as_str());
                output.push('\n');
            }
        }
        ProfileSuccess::Inspected(inspection) => {
            output.push_str(inspection.profile.as_str());
            output.push('\n');
            for variable in inspection.variables {
                output.push_str(variable.as_str());
                output.push('\n');
            }
        }
        ProfileSuccess::Set {
            profile,
            variable,
            mutation,
        } => {
            output.push_str(match mutation {
                Mutation::Created => "Created variable '",
                Mutation::Updated => "Updated variable '",
            });
            output.push_str(variable.as_str());
            output.push_str("' in profile '");
            output.push_str(profile.as_str());
            output.push_str("'.\n");
        }
        ProfileSuccess::Removed { profile, variable } => {
            output.push_str("Removed variable '");
            output.push_str(variable.as_str());
            output.push_str("' from profile '");
            output.push_str(profile.as_str());
            output.push_str("'.\n");
        }
    }
    output
}

#[cfg(target_os = "macos")]
fn run_status() -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            print!("{}", render_path_failure("Status"));
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let vault = ProfileOperations::new(&keys, &store).inspect_all(interaction_policy());
    let recovery = RecoveryOperations::new(&keys, &store).overview();
    let shell = diagnose_zsh(&paths);
    let current_shell = inherited_managed_state();
    let report = StatusReport {
        vault,
        recovery,
        shell,
        current_shell,
    };
    print!("{}", render_status(&report));
    report_diagnostic_errors(
        &report.vault,
        &report.recovery,
        &report.shell,
        &report.current_shell,
    );
    ExitCode::from(report.exit_code())
}

#[cfg(target_os = "macos")]
fn run_doctor() -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            print!("{}", render_path_failure("Doctor"));
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let vault = ProfileOperations::new(&keys, &store).readiness(interaction_policy());
    let recovery = RecoveryOperations::new(&keys, &store).overview();
    let shell = diagnose_zsh(&paths);
    let current_shell = inherited_managed_state();
    let report = DoctorReport {
        vault,
        recovery,
        shell,
        current_shell,
    };
    print!("{}", render_doctor(&report));
    report_diagnostic_errors(
        &report.vault,
        &report.recovery,
        &report.shell,
        &report.current_shell,
    );
    ExitCode::from(report.exit_code())
}

#[cfg(target_os = "macos")]
fn run_backup(destination: PathBuf) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let operations = ProfileOperations::new(&keys, &store);
    let writer = EncryptedBackupWriter::new(destination);
    match operations.backup_to(interaction_policy(), |envelope| writer.create(envelope)) {
        Ok(receipt) => {
            print!("{}", render_backup_success(receipt));
            eprintln!(
                "gschrank: this backup requires its exact macOS Keychain item; no master key was exported"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn render_backup_success(receipt: BackupReceipt) -> String {
    format!(
        "Created an encrypted vault backup at revision {}.\n",
        receipt.revision
    )
}

#[cfg(target_os = "macos")]
fn run_restore(source: PathBuf) -> ExitCode {
    let envelope = match EncryptedRestoreSource::new(source).read() {
        Ok(envelope) => envelope,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(error.exit_code());
        }
    };
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let mut confirmer = TerminalTypedConfirmer;
    match RestoreOperations::new(&keys, &store).restore_external(
        &envelope,
        interaction_policy(),
        &mut confirmer,
    ) {
        Ok(receipt) => {
            print!("{}", render_restore_success(receipt));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(target_os = "macos")]
fn run_recovery_restore(bundle_id: RecoveryBundleId) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let mut confirmer = TerminalTypedConfirmer;
    match RestoreOperations::new(&keys, &store).restore_bundle(
        bundle_id,
        interaction_policy(),
        &mut confirmer,
    ) {
        Ok(receipt) => {
            print!("{}", render_restore_success(receipt));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(target_os = "macos")]
fn run_recovery_purge(bundle_id: RecoveryBundleId) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let mut confirmer = TerminalTypedConfirmer;
    match RecoveryPurgeOperations::new(&keys, &store).purge(
        bundle_id,
        interaction_policy(),
        &mut confirmer,
    ) {
        Ok(receipt) => {
            print!("{}", render_recovery_purge_success(receipt));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn render_recovery_purge_success(receipt: RecoveryPurgeReceipt) -> String {
    format!(
        "Purged recovery bundle {}.\nRetired Keychain items: {}\nRetained shared Keychain items: {}\n",
        receipt.bundle_id.to_hex(),
        receipt.retired_key_count,
        receipt.retained_key_count
    )
}

fn render_restore_success(receipt: RestoreReceipt) -> String {
    let mut output = format!(
        "Restored the authenticated encrypted vault at revision {}.\n",
        receipt.revision
    );
    if let Some(bundle_id) = receipt.displaced_to {
        output.push_str("Previous live ciphertext retained as recovery bundle ");
        output.push_str(&bundle_id.to_hex());
        output.push_str(".\n");
    }
    output
}

#[cfg(target_os = "macos")]
fn run_rebuild() -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let mut confirmer = TerminalTypedConfirmer;
    match RebuildOperations::new(&keys, &store).rebuild(interaction_policy(), &mut confirmer) {
        Ok(receipt) => {
            print!("{}", render_rebuild_success(receipt));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn render_rebuild_success(receipt: RebuildReceipt) -> String {
    format!(
        "Rebuilt every profile and value under a new vault identity at revision 0.\nPrevious encrypted vault retained as recovery bundle {}.\nExisting shells keep their current environment snapshots; new shells use the rebuilt vault.\n",
        receipt.recovery_bundle.to_hex()
    )
}

#[cfg(target_os = "macos")]
fn run_reset(shell_wrapper: bool) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let operations = ResetOperations::new(&keys, &store);
    let mut confirmer = TerminalTypedConfirmer;
    let mut preparation_failure = None;
    let result = operations.reset(interaction_policy(), &mut confirmer, || {
        let prepared = resolve_zsh_config(&paths, None)
            .and_then(|resolved| disable_startup_for_reset(&resolved));
        prepared.map_err(|error| {
            let exit_code = error.exit_code();
            preparation_failure = Some(error);
            ResetPreparationError::new(exit_code)
        })
    });

    match result {
        Ok(receipt) => {
            print!("{}", render_reset_success(receipt, shell_wrapper));
            ExitCode::SUCCESS
        }
        Err(ResetError::PreparationFailed(error)) => {
            if let Some(source) = preparation_failure {
                eprintln!(
                    "gschrank: {source}; automatic startup loading was not changed and vault reset did not begin"
                );
            } else {
                eprintln!("gschrank: {}", ResetError::PreparationFailed(error));
            }
            ExitCode::from(error.exit_code())
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(target_os = "macos")]
fn disable_startup_for_reset(resolved: &ResolvedZshConfig) -> Result<(), ShellConfigurationError> {
    let state = resolved.editor.inspect()?;
    let Some(current) = state.configuration() else {
        return Ok(());
    };
    if current.profile().is_none() {
        return Ok(());
    }
    let success = configure_startup(&resolved.editor, current.with_profile(None))?;
    resolved.remember(success.configuration.shortcut())
}

fn render_reset_success(receipt: ResetReceipt, shell_wrapper: bool) -> String {
    let mut output = String::from("Initialized a new independently keyed empty vault.\n");
    output.push_str("Previous encrypted state retained as recovery bundle ");
    output.push_str(&receipt.recovery_bundle.to_hex());
    output.push_str(".\nAutomatic profile loading is off for new Zsh shells.\n");
    if !shell_wrapper {
        output.push_str(
            "The current shell was not changed; run 'gschrank unload' through the managed Zsh function or close this shell.\n",
        );
    }
    output
}

#[cfg(target_os = "macos")]
fn run_shell_uninstall(shell_wrapper: bool) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let result = resolve_zsh_config(&paths, None)
        .and_then(|resolved| remove_persistent_shell_integration(&resolved));
    match result {
        Ok(()) => {
            print!("{}", render_shell_uninstall_success(shell_wrapper));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}; persistent shell integration may require inspection");
            ExitCode::from(error.exit_code())
        }
    }
}

fn render_shell_uninstall_success(shell_wrapper: bool) -> &'static str {
    if shell_wrapper {
        "Removed persistent Zsh integration. The executable, encrypted vault, recovery bundles, Keychain items, and startup-file backup were retained.\n"
    } else {
        "Removed persistent Zsh integration. The executable, encrypted vault, recovery bundles, Keychain items, and startup-file backup were retained.\nThe current shell was not changed; run 'gschrank unload' through its still-loaded managed function or close this shell.\n"
    }
}

#[cfg(target_os = "macos")]
fn run_full_purge(shell_wrapper: bool) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let mut confirmer = TerminalTypedConfirmer;
    let mut preparation_failure = None;
    let result =
        FullPurgeOperations::new(&keys, &store).purge(interaction_policy(), &mut confirmer, || {
            let prepared = resolve_zsh_config(&paths, None)
                .and_then(|resolved| remove_persistent_shell_integration(&resolved));
            prepared.map_err(|error| {
                let exit_code = error.exit_code();
                preparation_failure = Some(error);
                FullPurgePreparationError::new(exit_code)
            })
        });

    match result {
        Ok(receipt) => {
            print!("{}", render_full_purge_success(receipt, shell_wrapper));
            ExitCode::SUCCESS
        }
        Err(FullPurgeError::PreparationFailed(error)) => {
            if let Some(source) = preparation_failure {
                eprintln!(
                    "gschrank: {source}; persistent shell integration may require inspection and destructive vault purge did not continue"
                );
            } else {
                eprintln!("gschrank: {}", FullPurgeError::PreparationFailed(error));
            }
            ExitCode::from(error.exit_code())
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(target_os = "macos")]
fn remove_persistent_shell_integration(
    resolved: &ResolvedZshConfig,
) -> Result<(), ShellConfigurationError> {
    resolved.editor.remove()?;
    resolved.preferences.remove()?;
    Ok(())
}

fn render_full_purge_success(receipt: FullPurgeReceipt, shell_wrapper: bool) -> String {
    let mut output = format!(
        "Purged local encrypted vault, recovery, and configuration state.\nRetired Keychain items: {}\n",
        receipt.retired_key_count
    );
    if receipt.unauthenticated_artifact_count > 0 {
        output.push_str("Unauthenticated encrypted artifacts removed without guessing keys: ");
        output.push_str(&receipt.unauthenticated_artifact_count.to_string());
        output.push('\n');
    }
    output.push_str(
        "Persistent Zsh integration was removed.\nThis operation does not claim secure erasure.\n",
    );
    if !shell_wrapper {
        output.push_str(
            "The current shell was not changed; close it before running commands that could inherit its existing environment.\n",
        );
    }
    output
}

#[cfg(target_os = "macos")]
fn run_recovery_list() -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    match RecoveryOperations::new(&keys, &store).list(interaction_policy()) {
        Ok(list) => {
            print!("{}", render_recovery_list(&list));
            ExitCode::from(list.exit_code())
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn render_recovery_list(list: &RecoveryList) -> String {
    let mut output = String::from("Full purge pending: ");
    output.push_str(if list.full_purge_pending { "yes" } else { "no" });
    output.push_str("\nRecovery bundles:\n");
    if list.bundles.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for bundle in &list.bundles {
            output.push_str("  ");
            output.push_str(&bundle.id.to_hex());
            output.push_str("\n    Created: ");
            output.push_str(&bundle.created_at_unix_seconds.to_string());
            output.push_str(" Unix seconds\n    Reason: ");
            output.push_str(bundle.reason.label());
            output.push_str("\n    Vault ID: ");
            output.push_str(
                &bundle
                    .vault_id
                    .map_or_else(|| "unavailable".to_owned(), crate::VaultId::to_hex),
            );
            output.push_str("\n    Key ID: ");
            output.push_str(
                &bundle
                    .key_id
                    .map_or_else(|| "unavailable".to_owned(), crate::KeyId::to_hex),
            );
            output.push_str("\n    Authentication: ");
            output.push_str(bundle.authentication.label());
            output.push('\n');
        }
    }
    output.push_str("Recovery purges pending:\n");
    if list.purge_pending.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for id in &list.purge_pending {
            output.push_str("  ");
            output.push_str(&id.to_hex());
            output.push('\n');
        }
    }
    output
}

#[cfg(target_os = "macos")]
fn diagnose_zsh(paths: &MacOsPaths) -> Result<ZshDiagnostic, ShellConfigurationError> {
    let resolved = resolve_zsh_config(paths, None)?;
    resolved
        .editor
        .diagnose(resolved.shortcut_default())
        .map_err(Into::into)
}

#[cfg(target_os = "macos")]
fn report_diagnostic_errors<T>(
    vault: &Result<T, ProfileOperationError>,
    recovery: &Result<RecoveryOverview, RecoveryOperationError>,
    shell: &Result<ZshDiagnostic, ShellConfigurationError>,
    current_shell: &Result<ManagedState, ManagedStateError>,
) {
    if let Err(error) = vault {
        eprintln!("gschrank: {error}");
    }
    if let Err(error) = recovery
        && !matches!(
            (vault, error.kind()),
            (
                Err(ProfileOperationError::NotInitialized),
                crate::vault_store::VaultStoreErrorKind::MissingState
            )
        )
    {
        eprintln!("gschrank: {error}");
    }
    if let Err(error) = shell {
        eprintln!("gschrank: {error}");
    }
    if let Err(error) = current_shell {
        eprintln!("gschrank: {error}");
    }
}

#[cfg(target_os = "macos")]
fn render_path_failure(command: &str) -> String {
    format!(
        "{command}: unavailable\nLifecycle: unavailable\nVault: unavailable\nInitialization candidate: unknown\nRebuild candidate: unknown\nRecovery bundles: unknown\nRecovery purges pending: unknown\nFull purge pending: unknown\nShell integration: unavailable\nRemediation: use private, user-owned local paths and retry.\n"
    )
}

#[cfg(target_os = "macos")]
fn render_status(report: &StatusReport) -> String {
    let mut output = String::new();
    output.push_str("Status: ");
    output.push_str(status_outcome(report));
    output.push('\n');
    output.push_str("Lifecycle: ");
    output.push_str(lifecycle_label(&report.vault, &report.recovery));
    output.push('\n');
    match &report.vault {
        Ok(vault) => {
            output.push_str("Vault: ready (revision ");
            output.push_str(&vault.revision.to_string());
            output.push_str(")\n");
        }
        Err(_) => output.push_str("Vault: unavailable\n"),
    }
    append_recovery_overview(&mut output, &report.recovery);
    append_shell_status(&mut output, report.shell.as_ref().ok());
    append_current_shell_status(&mut output, &report.current_shell, true);
    if let Ok(vault) = &report.vault {
        output.push_str("Profiles:\n");
        if vault.profiles.is_empty() {
            output.push_str("  (none)\n");
        }
        for profile in &vault.profiles {
            output.push_str("  ");
            output.push_str(profile.profile.as_str());
            output.push('\n');
            for variable in &profile.variables {
                output.push_str("    ");
                output.push_str(variable.as_str());
                output.push('\n');
            }
        }
    }
    output
}

#[cfg(target_os = "macos")]
fn render_doctor(report: &DoctorReport) -> String {
    let mut output = String::new();
    output.push_str("Doctor: ");
    output.push_str(doctor_outcome(report));
    output.push('\n');
    append_vault_doctor(&mut output, &report.vault);
    append_recovery_overview(&mut output, &report.recovery);
    append_shell_status(&mut output, report.shell.as_ref().ok());
    append_current_shell_status(&mut output, &report.current_shell, false);
    output.push_str("Remediation: ");
    output.push_str(doctor_remediation(report));
    output.push('\n');
    output
}

#[cfg(target_os = "macos")]
fn append_recovery_overview(
    output: &mut String,
    overview: &Result<RecoveryOverview, RecoveryOperationError>,
) {
    if let Ok(overview) = overview {
        output.push_str("Initialization candidate: ");
        output.push_str(if overview.initialization_pending {
            "present"
        } else {
            "absent"
        });
        output.push_str("\nRebuild candidate: ");
        output.push_str(if overview.rebuild_pending {
            "present"
        } else {
            "absent"
        });
        output.push_str("\nRecovery bundles: ");
        output.push_str(&overview.bundle_count.to_string());
        output.push_str("\nRecovery purges pending: ");
        output.push_str(&overview.purge_pending_count.to_string());
        output.push_str("\nFull purge pending: ");
        output.push_str(if overview.full_purge_pending {
            "yes"
        } else {
            "no"
        });
        output.push('\n');
    } else {
        output.push_str("Initialization candidate: unknown\n");
        output.push_str("Rebuild candidate: unknown\n");
        output.push_str("Recovery bundles: unknown\n");
        output.push_str("Recovery purges pending: unknown\n");
        output.push_str("Full purge pending: unknown\n");
    }
}

#[cfg(target_os = "macos")]
fn append_vault_doctor(
    output: &mut String,
    readiness: &Result<VaultReadiness, ProfileOperationError>,
) {
    match readiness {
        Ok(readiness) => {
            output.push_str("Vault storage: readable and private\n");
            output.push_str("Envelope: supported and authenticated\n");
            output.push_str("Keychain item: present\n");
            output.push_str("Revision: ");
            output.push_str(&readiness.revision.to_string());
            output.push('\n');
        }
        Err(ProfileOperationError::NotInitialized) => {
            output.push_str("Vault storage: not initialized\n");
            output.push_str("Envelope: not checked\n");
            output.push_str("Keychain item: not checked\n");
        }
        Err(ProfileOperationError::VaultKeyMissing) => {
            output.push_str("Vault storage: readable\n");
            output.push_str("Envelope: supported header\n");
            output.push_str("Keychain item: missing\n");
        }
        Err(ProfileOperationError::InvalidKeyMaterial) => {
            output.push_str("Vault storage: readable\n");
            output.push_str("Envelope: supported header\n");
            output.push_str("Keychain item: invalid\n");
        }
        Err(ProfileOperationError::SecureStore(_)) => {
            output.push_str("Vault storage: readable\n");
            output.push_str("Envelope: supported header\n");
            output.push_str("Keychain item: unavailable\n");
        }
        Err(ProfileOperationError::Vault(_)) => {
            output.push_str("Vault storage: readable\n");
            output.push_str("Envelope: invalid or unauthenticated\n");
            output.push_str("Keychain item: unavailable\n");
        }
        Err(ProfileOperationError::Store(_)) => {
            output.push_str("Vault storage: unavailable\n");
            output.push_str("Envelope: not checked\n");
            output.push_str("Keychain item: not checked\n");
        }
        Err(
            ProfileOperationError::Domain(_)
            | ProfileOperationError::CommitNotCompleted
            | ProfileOperationError::CommitOutcomeIndeterminate,
        ) => {
            output.push_str("Vault storage: unavailable\n");
            output.push_str("Envelope: unavailable\n");
            output.push_str("Keychain item: unavailable\n");
        }
    }
}

#[cfg(target_os = "macos")]
fn append_shell_status(output: &mut String, shell: Option<&ZshDiagnostic>) {
    let Some(shell) = shell else {
        output.push_str("Shell integration: unavailable\n");
        output.push_str("Startup profile: unknown\n");
        output.push_str("Canonical shell name: unknown\n");
        output.push_str("Shortcut: unknown\n");
        return;
    };
    match &shell.integration {
        ShellIntegrationState::Absent => {
            output.push_str("Shell integration: absent\n");
            output.push_str("Startup profile: not configured\n");
        }
        ShellIntegrationState::Installed(configuration) => {
            output.push_str("Shell integration: installed\n");
            output.push_str("Startup profile: ");
            if let Some(profile) = configuration.profile() {
                output.push_str(profile.as_str());
            } else {
                output.push_str("off");
            }
            output.push('\n');
        }
    }
    output.push_str("Canonical shell name: ");
    output.push_str(if shell.canonical_conflict {
        "conflicting"
    } else {
        "available"
    });
    output.push('\n');
    output.push_str("Shortcut: ");
    output.push_str(shortcut_label(shell.shortcut));
    output.push('\n');
}

#[cfg(target_os = "macos")]
fn append_current_shell_status(
    output: &mut String,
    current: &Result<ManagedState, ManagedStateError>,
    include_names: bool,
) {
    if let Ok(state) = current {
        output.push_str("Current shell: ");
        if let Some(profile) = state.active_profile() {
            if include_names {
                output.push_str("active profile ");
                output.push_str(profile.as_str());
            } else {
                output.push_str("valid active metadata");
            }
        } else {
            output.push_str("inactive");
        }
        output.push('\n');
        if include_names {
            output.push_str("Managed variables:\n");
            if state.managed_names().is_empty() {
                output.push_str("  (none)\n");
            } else {
                for name in state.managed_names() {
                    output.push_str("  ");
                    output.push_str(name.as_str());
                    output.push('\n');
                }
            }
        } else {
            output.push_str("Managed-variable metadata: valid (count ");
            output.push_str(&state.managed_names().len().to_string());
            output.push_str(")\n");
        }
    } else {
        output.push_str("Current shell: invalid managed metadata\n");
        if include_names {
            output.push_str("Managed variables: unavailable\n");
        } else {
            output.push_str("Managed-variable metadata: invalid\n");
        }
    }
}

#[cfg(target_os = "macos")]
const fn shortcut_label(shortcut: ShortcutDiagnostic) -> &'static str {
    match shortcut {
        ShortcutDiagnostic::Enabled => "enabled",
        ShortcutDiagnostic::Available => "available",
        ShortcutDiagnostic::Conflicting => "conflicting",
        ShortcutDiagnostic::Shadowed => "shadowed",
        ShortcutDiagnostic::Disabled => "disabled",
    }
}

#[cfg(target_os = "macos")]
const fn vault_lifecycle(error: ProfileOperationError) -> &'static str {
    match error {
        ProfileOperationError::NotInitialized => "not initialized",
        ProfileOperationError::VaultKeyMissing
        | ProfileOperationError::InvalidKeyMaterial
        | ProfileOperationError::Vault(_) => "frozen",
        ProfileOperationError::SecureStore(_)
        | ProfileOperationError::Domain(_)
        | ProfileOperationError::Store(_)
        | ProfileOperationError::CommitNotCompleted
        | ProfileOperationError::CommitOutcomeIndeterminate => "unavailable",
    }
}

#[cfg(target_os = "macos")]
fn lifecycle_label<T>(
    vault: &Result<T, ProfileOperationError>,
    recovery: &Result<RecoveryOverview, RecoveryOperationError>,
) -> &'static str {
    match (vault, recovery) {
        (
            _,
            Ok(RecoveryOverview {
                full_purge_pending: true,
                ..
            }),
        ) => "full purge pending",
        (
            _,
            Ok(RecoveryOverview {
                purge_pending_count: 1..,
                ..
            }),
        ) => "recovery purge pending",
        (
            _,
            Ok(RecoveryOverview {
                rebuild_pending: true,
                ..
            }),
        ) => "rebuild pending",
        (
            Err(ProfileOperationError::NotInitialized),
            Ok(RecoveryOverview {
                initialization_pending: true,
                ..
            }),
        ) => "initialization pending",
        (
            Ok(_),
            Ok(RecoveryOverview {
                initialization_pending: true,
                ..
            }),
        ) => "ready with conflicting initialization state",
        (Ok(_), Ok(_)) => "ready",
        (Err(error), _) => vault_lifecycle(*error),
        (Ok(_), Err(_)) => "unavailable",
    }
}

#[cfg(target_os = "macos")]
fn status_outcome(report: &StatusReport) -> &'static str {
    match (&report.vault, &report.recovery) {
        (
            _,
            Ok(RecoveryOverview {
                full_purge_pending: true,
                ..
            }),
        ) => "full purge pending",
        (
            _,
            Ok(RecoveryOverview {
                purge_pending_count: 1..,
                ..
            }),
        ) => "recovery purge pending",
        (
            _,
            Ok(RecoveryOverview {
                rebuild_pending: true,
                ..
            }),
        ) => "rebuild pending",
        (
            Err(ProfileOperationError::NotInitialized),
            Ok(RecoveryOverview {
                initialization_pending: true,
                ..
            }),
        ) => "initialization pending",
        _ => match report.vault {
            Err(error) => vault_lifecycle(error),
            Ok(_) if report.exit_code() == 0 => "ready",
            Ok(_) => "action required",
        },
    }
}

#[cfg(target_os = "macos")]
fn doctor_outcome(report: &DoctorReport) -> &'static str {
    match (&report.vault, &report.recovery) {
        (
            _,
            Ok(RecoveryOverview {
                full_purge_pending: true,
                ..
            }),
        ) => "full purge pending",
        (
            _,
            Ok(RecoveryOverview {
                purge_pending_count: 1..,
                ..
            }),
        ) => "recovery purge pending",
        (
            _,
            Ok(RecoveryOverview {
                rebuild_pending: true,
                ..
            }),
        ) => "rebuild pending",
        (
            Err(ProfileOperationError::NotInitialized),
            Ok(RecoveryOverview {
                initialization_pending: true,
                ..
            }),
        ) => "initialization pending",
        _ => match report.vault {
            Err(ProfileOperationError::NotInitialized) => "not initialized",
            Err(
                ProfileOperationError::VaultKeyMissing
                | ProfileOperationError::InvalidKeyMaterial
                | ProfileOperationError::Vault(_),
            ) => "frozen",
            Err(_) => "unhealthy",
            Ok(_) if report.exit_code() == 0 => "healthy",
            Ok(_) => "action required",
        },
    }
}

#[cfg(target_os = "macos")]
fn doctor_remediation(report: &DoctorReport) -> &'static str {
    if let Some(remediation) = pending_purge_remediation(&report.recovery) {
        return remediation;
    }
    if matches!(
        (&report.vault, &report.recovery),
        (
            Err(ProfileOperationError::NotInitialized),
            Ok(RecoveryOverview {
                initialization_pending: true,
                ..
            })
        )
    ) {
        return "run 'gschrank init' to safely resume the reserved initialization.";
    }
    if report.vault.is_ok()
        && report
            .recovery
            .is_ok_and(|overview| overview.initialization_pending)
    {
        return "preserve the conflicting initialization candidate and resolve it through an explicit recovery lifecycle operation.";
    }
    if report
        .recovery
        .is_ok_and(|overview| overview.rebuild_pending)
    {
        return "run 'gschrank rebuild' to safely resume the reserved rebuild.";
    }
    if let Err(error) = report.recovery
        && report.vault.is_ok()
    {
        return match error.kind() {
            crate::vault_store::VaultStoreErrorKind::Conflict => {
                "leave recovery state unchanged and inspect the ambiguous internal recovery artifacts before retrying."
            }
            crate::vault_store::VaultStoreErrorKind::OutcomeIndeterminate => {
                "leave recovery state unchanged and inspect whether the last recovery commit completed before retrying."
            }
            crate::vault_store::VaultStoreErrorKind::MissingState
            | crate::vault_store::VaultStoreErrorKind::UnsafePath
            | crate::vault_store::VaultStoreErrorKind::PermissionDenied
            | crate::vault_store::VaultStoreErrorKind::LockFailure
            | crate::vault_store::VaultStoreErrorKind::UnsupportedStorage
            | crate::vault_store::VaultStoreErrorKind::IoFailure => {
                "leave recovery state unchanged, restore private local storage, and retry."
            }
        };
    }
    match report.vault {
        Err(ProfileOperationError::NotInitialized) => {
            "run 'gschrank config' for guided setup or 'gschrank init' for an empty vault."
        }
        Err(ProfileOperationError::SecureStore(_)) => {
            "unlock or permit macOS Keychain access, then retry."
        }
        Err(ProfileOperationError::VaultKeyMissing | ProfileOperationError::InvalidKeyMaterial) => {
            "do not overwrite the vault; use an explicit recovery or fresh-vault workflow."
        }
        Err(ProfileOperationError::Vault(_)) => {
            "do not reset automatically; preserve the vault and use an explicit recovery workflow."
        }
        Err(ProfileOperationError::Store(error)) => match error.kind() {
            crate::vault_store::VaultStoreErrorKind::UnsafePath
            | crate::vault_store::VaultStoreErrorKind::PermissionDenied
            | crate::vault_store::VaultStoreErrorKind::UnsupportedStorage => {
                "restore private, user-owned local vault storage and retry."
            }
            crate::vault_store::VaultStoreErrorKind::Conflict
            | crate::vault_store::VaultStoreErrorKind::MissingState
            | crate::vault_store::VaultStoreErrorKind::LockFailure
            | crate::vault_store::VaultStoreErrorKind::IoFailure
            | crate::vault_store::VaultStoreErrorKind::OutcomeIndeterminate => {
                "leave the vault unchanged, resolve the local storage failure, and retry."
            }
        },
        Err(
            ProfileOperationError::Domain(_)
            | ProfileOperationError::CommitNotCompleted
            | ProfileOperationError::CommitOutcomeIndeterminate,
        ) => "leave the vault unchanged and inspect its state before retrying.",
        Ok(_) => match &report.shell {
            Err(_) => "repair the reported Zsh configuration or preference failure and retry.",
            Ok(shell) if shell.integration == ShellIntegrationState::Absent => {
                "run 'gschrank config' to install the managed Zsh integration."
            }
            Ok(shell) if shell.canonical_conflict => {
                "remove or rename the unmanaged 'gschrank' shell definition, then rerun configuration."
            }
            Ok(_) if report.current_shell.is_err() => {
                "open a fresh Zsh session to discard invalid inherited Gschrank metadata."
            }
            Ok(_) => "none.",
        },
    }
}

#[cfg(target_os = "macos")]
fn pending_purge_remediation(
    recovery: &Result<RecoveryOverview, RecoveryOperationError>,
) -> Option<&'static str> {
    let overview = recovery.as_ref().ok()?;
    if overview.full_purge_pending {
        Some("run 'gschrank purge' to resume the staged destructive purge.")
    } else if overview.purge_pending_count > 0 {
        Some(
            "run 'gschrank recovery list', then resume the listed pending purge with 'gschrank recovery purge <bundle-id>'.",
        )
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn run_init() -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let initializer = Initializer::new(&keys, &store);
    let interaction = interaction_policy();

    match initializer.initialize(interaction) {
        Ok(InitOutcome::Created { .. }) => {
            println!("Initialized an empty encrypted vault.");
            ExitCode::SUCCESS
        }
        Ok(InitOutcome::AlreadyInitialized { .. }) => {
            println!("Gschrank is already initialized; nothing changed.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(target_os = "macos")]
fn run_import(profile: &ProfileName, options: ImportOptions) -> ExitCode {
    if std::io::stdin().is_terminal() {
        let error = ImportCommandError::TerminalStdin;
        eprintln!("gschrank: {error}");
        return ExitCode::from(error.exit_code());
    }
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let operations = ProfileOperations::new(&keys, &store);
    let interaction = if std::io::stderr().is_terminal() {
        InteractionPolicy::AllowPrompt
    } else {
        InteractionPolicy::FailFast
    };
    let stdin = std::io::stdin();
    match execute_import(
        &operations,
        profile,
        options,
        interaction,
        false,
        stdin.lock(),
    ) {
        Ok(outcome) => {
            let imported = matches!(outcome, ImportOutcome::Imported(_));
            print!("{}", render_import_outcome(profile, outcome));
            if imported {
                eprintln!(
                    "gschrank: if stdin came from a plaintext file, that file still exists; secure or remove it separately after verification"
                );
            }
            ExitCode::SUCCESS
        }
        Err(ImportCommandError::Operation(ImportOperationError::Collisions(names))) => {
            eprintln!(
                "gschrank: import would replace existing variables; rerun with --replace-existing to authorize the complete import"
            );
            for name in names {
                eprintln!("{}", name.as_str());
            }
            ExitCode::from(14)
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

fn render_import_outcome(profile: &ProfileName, outcome: ImportOutcome) -> String {
    let mut output = String::new();
    match outcome {
        ImportOutcome::NoVariables => {
            output.push_str("No variables were found; nothing changed.\n");
        }
        ImportOutcome::DryRun {
            plan,
            replace_existing,
        } => {
            if plan.created.is_empty() && plan.collisions.is_empty() {
                output.push_str("No variables were found; the dry run would change nothing.\n");
                return output;
            }
            output.push_str("Dry run for profile '");
            output.push_str(profile.as_str());
            output.push_str("'; no vault changes were made.\n");
            append_import_names(&mut output, "Would add", &plan.created);
            append_import_names(
                &mut output,
                if replace_existing {
                    "Would replace"
                } else {
                    "Collisions"
                },
                &plan.collisions,
            );
        }
        ImportOutcome::Imported(receipt) => {
            let count = receipt.plan.created.len() + receipt.plan.collisions.len();
            output.push_str("Imported ");
            output.push_str(&count.to_string());
            output.push_str(" variable(s) into profile '");
            output.push_str(profile.as_str());
            output.push_str("'.\n");
            append_import_names(&mut output, "Created", &receipt.plan.created);
            append_import_names(&mut output, "Replaced", &receipt.plan.collisions);
        }
    }
    output
}

fn append_import_names(output: &mut String, label: &str, names: &[EnvironmentName]) {
    if names.is_empty() {
        return;
    }
    output.push_str(label);
    output.push_str(":\n");
    for name in names {
        output.push_str(name.as_str());
        output.push('\n');
    }
}

#[cfg(target_os = "macos")]
fn run_profile(command: ProfileCommand) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let operations = ProfileOperations::new(&keys, &store);
    let interaction = interaction_policy();

    let result: Result<ProfileSuccess, ProfileCommandError> = match command {
        ProfileCommand::Create(profile) => {
            let output = profile.clone();
            operations
                .create(profile, interaction)
                .map(|_| ProfileSuccess::Created(output))
                .map_err(Into::into)
        }
        ProfileCommand::Rename { old, new } => {
            let output_old = old.clone();
            let output_new = new.clone();
            rename_profile_and_startup(&paths, &operations, &old, new, interaction).map(|()| {
                ProfileSuccess::Renamed {
                    old: output_old,
                    new: output_new,
                }
            })
        }
        ProfileCommand::Delete(profile) => {
            delete_profile_with_startup_guard(&paths, &operations, &profile, interaction)
                .map(|()| ProfileSuccess::Deleted(profile))
        }
        ProfileCommand::List => operations
            .list(interaction)
            .map(ProfileSuccess::Listed)
            .map_err(Into::into),
        ProfileCommand::Inspect(profile) => operations
            .inspect(&profile, interaction)
            .map(ProfileSuccess::Inspected)
            .map_err(Into::into),
    };

    match result {
        Ok(success) => {
            print!("{}", render_profile_success(success));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(target_os = "macos")]
fn rename_profile_and_startup<K, S>(
    paths: &MacOsPaths,
    operations: &ProfileOperations<'_, K, S>,
    old: &ProfileName,
    new: ProfileName,
    interaction: InteractionPolicy,
) -> Result<(), ProfileCommandError>
where
    K: crate::key_provider::KeyProvider,
    S: crate::vault_store::VaultStore,
{
    let resolved = resolve_zsh_config(paths, None)?;
    rename_profile_and_startup_using(&resolved.editor, operations, old, new, interaction)
}

#[cfg(target_os = "macos")]
fn rename_profile_and_startup_using<K, S>(
    editor: &ZshConfigEditor,
    operations: &ProfileOperations<'_, K, S>,
    old: &ProfileName,
    new: ProfileName,
    interaction: InteractionPolicy,
) -> Result<(), ProfileCommandError>
where
    K: crate::key_provider::KeyProvider,
    S: crate::vault_store::VaultStore,
{
    let state = editor.inspect()?;
    let Some(configuration) = state.configuration() else {
        operations.rename(old, new, interaction)?;
        return Ok(());
    };
    if configuration.profile() != Some(old) {
        operations.rename(old, new, interaction)?;
        return Ok(());
    }

    operations.preflight_rename(old, &new, interaction)?;
    let previous = configuration.clone();
    let replacement = configuration.with_profile(Some(new.clone()));
    let replacement_block = ZshEmitter::emit_managed_block(replacement);
    editor.configure(&replacement_block)?;

    match operations.rename(old, new, interaction) {
        Ok(_) => Ok(()),
        Err(ProfileOperationError::CommitOutcomeIndeterminate) => Err(
            ProfileCommandError::Profile(ProfileOperationError::CommitOutcomeIndeterminate),
        ),
        Err(error) => {
            let rollback = ZshEmitter::emit_managed_block(previous);
            if editor.configure(&rollback).is_err() {
                Err(ProfileCommandError::RenameRollbackFailed)
            } else {
                Err(ProfileCommandError::Profile(error))
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn delete_profile_with_startup_guard<K, S>(
    paths: &MacOsPaths,
    operations: &ProfileOperations<'_, K, S>,
    profile: &ProfileName,
    interaction: InteractionPolicy,
) -> Result<(), ProfileCommandError>
where
    K: crate::key_provider::KeyProvider,
    S: crate::vault_store::VaultStore,
{
    let resolved = resolve_zsh_config(paths, None)?;
    delete_profile_with_startup_guard_using(&resolved.editor, operations, profile, interaction)
}

#[cfg(target_os = "macos")]
fn delete_profile_with_startup_guard_using<K, S>(
    editor: &ZshConfigEditor,
    operations: &ProfileOperations<'_, K, S>,
    profile: &ProfileName,
    interaction: InteractionPolicy,
) -> Result<(), ProfileCommandError>
where
    K: crate::key_provider::KeyProvider,
    S: crate::vault_store::VaultStore,
{
    if editor
        .inspect()?
        .configuration()
        .and_then(StartupConfiguration::profile)
        == Some(profile)
    {
        return Err(ProfileCommandError::ConfiguredStartupProfile);
    }
    operations.delete(profile, interaction)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_set(profile: &ProfileName, variable: EnvironmentName, input: SecretInputMode) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let operations = ProfileOperations::new(&keys, &store);
    let interaction = interaction_policy();

    let output_profile = ProfileName::clone(profile);
    let output_variable = variable.clone();
    match execute_set(&operations, profile, variable, interaction, || {
        read_secret(input)
    }) {
        Ok(receipt) => {
            print!(
                "{}",
                render_profile_success(ProfileSuccess::Set {
                    profile: output_profile,
                    variable: output_variable,
                    mutation: receipt.mutation,
                })
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(target_os = "macos")]
fn run_remove(profile: &ProfileName, variable: &EnvironmentName) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    let operations = ProfileOperations::new(&keys, &store);
    let interaction = interaction_policy();
    let output_profile = ProfileName::clone(profile);
    let output_variable = EnvironmentName::clone(variable);

    match operations.remove(profile, variable, interaction) {
        Ok(_) => {
            print!(
                "{}",
                render_profile_success(ProfileSuccess::Removed {
                    profile: output_profile,
                    variable: output_variable,
                })
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(target_os = "macos")]
fn run_startup(command: StartupCommand) -> ExitCode {
    let paths = match MacOsPaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(13);
        }
    };
    let resolved = match resolve_zsh_config(&paths, None) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(error.exit_code());
        }
    };

    let requested_profile = match command {
        StartupCommand::Set(profile) => {
            let keys = MacOsKeychainProvider::new();
            let store = LocalVaultStore::new(paths.data_directory().to_owned());
            if let Err(error) =
                ProfileOperations::new(&keys, &store).inspect(&profile, interaction_policy())
            {
                eprintln!("gschrank: {error}");
                return ExitCode::from(error.exit_code());
            }
            Some(profile)
        }
        StartupCommand::Off => None,
    };

    let state = match resolved.editor.inspect() {
        Ok(state) => state,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(error.exit_code());
        }
    };
    let base = state
        .configuration()
        .cloned()
        .unwrap_or_else(|| StartupConfiguration::new(None, resolved.shortcut_default()));
    let requested = base.with_profile(requested_profile);

    match configure_startup(&resolved.editor, requested) {
        Ok(success) => {
            if let Err(error) = resolved.remember(success.configuration.shortcut()) {
                eprintln!(
                    "gschrank: the Zsh startup file was updated, but its selected path could not be saved: {error}"
                );
                return ExitCode::from(error.exit_code());
            }
            if success.shortcut_conflict {
                eprintln!(
                    "gschrank: the optional 'gsch' name is already in use; installed only the canonical 'gschrank' function"
                );
            }
            print!("{}", render_startup_success(&success));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("gschrank: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(target_os = "macos")]
fn configure_startup(
    editor: &ZshConfigEditor,
    requested: StartupConfiguration,
) -> Result<StartupSuccess, ZshConfigError> {
    let block = ZshEmitter::emit_managed_block(requested.clone());
    match editor.configure(&block) {
        Ok(edit) => Ok(StartupSuccess {
            edit,
            configuration: requested,
            shortcut_conflict: false,
        }),
        Err(ZshConfigError::ShortcutNameConflict) if requested.shortcut() => {
            let configuration = requested.without_shortcut();
            let block = ZshEmitter::emit_managed_block(configuration.clone());
            let edit = editor.configure(&block)?;
            Ok(StartupSuccess {
                edit,
                configuration,
                shortcut_conflict: true,
            })
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "macos")]
fn render_startup_success(success: &StartupSuccess) -> String {
    let mut output = String::new();
    match (success.configuration.profile(), success.edit) {
        (Some(profile), ShellConfigEdit::Unchanged) => {
            output.push_str("Profile '");
            output.push_str(profile.as_str());
            output.push_str("' is already configured for new Zsh shells; nothing changed.\n");
        }
        (Some(profile), ShellConfigEdit::Installed | ShellConfigEdit::Updated) => {
            output.push_str("Configured profile '");
            output.push_str(profile.as_str());
            output.push_str("' for new Zsh shells.\n");
        }
        (None, ShellConfigEdit::Unchanged) => {
            output.push_str("Automatic profile loading is already off; nothing changed.\n");
        }
        (None, ShellConfigEdit::Installed | ShellConfigEdit::Updated) => {
            output.push_str(
                "Turned off automatic profile loading for new Zsh shells; shell integration remains installed.\n",
            );
        }
    }
    if success.edit != ShellConfigEdit::Unchanged {
        output.push_str("The current shell was not changed; open a new shell or run 'exec zsh'.\n");
    }
    output
}

fn run_shell_parent(command: ShellParentCommand) -> ExitCode {
    let operation = match command {
        ShellParentCommand::Load(_profile) | ShellParentCommand::StartupLoad(_profile) => "load",
        ShellParentCommand::Reload => "reload",
        ShellParentCommand::Unload => "unload",
    };
    eprintln!(
        "gschrank: '{operation}' must run through the managed Zsh function to change the current shell; install or refresh shell integration first"
    );
    ExitCode::from(16)
}

fn run_shell_init(shortcut: bool) -> ExitCode {
    let source = ZshEmitter::new().emit_wrapper(shortcut);
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(source.as_bytes())
        .and_then(|()| stdout.flush())
        .is_err()
    {
        eprintln!("gschrank: failed to write the Zsh wrapper");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(target_os = "macos")]
fn inherited_managed_state() -> Result<ManagedState, ManagedStateError> {
    let protocol = std::env::var_os(ENV_PROTOCOL_NAME);
    let active_profile = std::env::var_os(ACTIVE_PROFILE_NAME);
    let managed_names = std::env::var_os(MANAGED_KEYS_NAME);
    if [&protocol, &active_profile, &managed_names]
        .into_iter()
        .any(|value| value.as_ref().is_some_and(|value| value.to_str().is_none()))
    {
        return Err(ManagedStateError::InvalidManagedNames);
    }
    ManagedState::from_metadata(
        protocol.as_deref().and_then(std::ffi::OsStr::to_str),
        active_profile.as_deref().and_then(std::ffi::OsStr::to_str),
        managed_names.as_deref().and_then(std::ffi::OsStr::to_str),
    )
}

#[cfg(target_os = "macos")]
fn run_emit_zsh(context: OperationContext, operation: EmitOperation) -> ExitCode {
    if std::io::stdout().is_terminal() {
        eprintln!("gschrank: the private shell emitter refuses terminal output");
        return ExitCode::from(16);
    }
    let current = match inherited_managed_state() {
        Ok(state) => state,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(16);
        }
    };

    let emitter = ZshEmitter::new();
    let source = match operation {
        EmitOperation::Unload => emitter.emit_cleanup(current.managed_names()),
        EmitOperation::Load(profile) => {
            match authenticated_snapshot(&profile, interaction_policy()) {
                Ok(snapshot) => {
                    let transition = ShellTransition::load(current, snapshot, context);
                    emitter.emit_apply(&transition)
                }
                Err(error) => {
                    eprintln!("gschrank: {error}");
                    return ExitCode::from(error.exit_code());
                }
            }
        }
        EmitOperation::Reload => {
            let profile = match ShellTransition::reload_profile(&current) {
                Ok(profile) => profile,
                Err(error) => {
                    eprintln!("gschrank: {error}");
                    return ExitCode::from(16);
                }
            };
            match authenticated_snapshot(&profile, interaction_policy()) {
                Ok(snapshot) => {
                    let transition = ShellTransition::load(current, snapshot, context);
                    emitter.emit_apply(&transition)
                }
                Err(error) => {
                    eprintln!("gschrank: {error}");
                    return ExitCode::from(error.exit_code());
                }
            }
        }
    };
    let source = match source {
        Ok(source) => source,
        Err(error) => {
            eprintln!("gschrank: {error}");
            return ExitCode::from(1);
        }
    };
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(&source)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        eprintln!("gschrank: failed to write the shell transition");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

#[cfg(target_os = "macos")]
fn authenticated_snapshot(
    profile: &ProfileName,
    interaction: InteractionPolicy,
) -> Result<crate::domain::ProfileSnapshot, SnapshotLoadError> {
    let paths = MacOsPaths::discover().map_err(SnapshotLoadError::Paths)?;
    let keys = MacOsKeychainProvider::new();
    let store = LocalVaultStore::new(paths.data_directory().to_owned());
    ProfileOperations::new(&keys, &store)
        .snapshot(profile, interaction)
        .map_err(SnapshotLoadError::Profile)
}

#[cfg(target_os = "macos")]
enum SnapshotLoadError {
    Paths(MacOsPathError),
    Profile(crate::profiles::ProfileOperationError),
}

#[cfg(target_os = "macos")]
impl SnapshotLoadError {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Paths(_) => 13,
            Self::Profile(error) => error.exit_code(),
        }
    }
}

#[cfg(target_os = "macos")]
impl std::fmt::Display for SnapshotLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Paths(error) => std::fmt::Display::fmt(error, formatter),
            Self::Profile(error) => std::fmt::Display::fmt(error, formatter),
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn run_emit_zsh(_context: OperationContext, _operation: EmitOperation) -> ExitCode {
    eprintln!("gschrank: this build does not support encrypted profiles on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_config(_explicit_rc_file: Option<PathBuf>) -> ExitCode {
    eprintln!("gschrank: this build does not support guided macOS and Zsh configuration");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_import(_profile: &ProfileName, _options: ImportOptions) -> ExitCode {
    eprintln!("gschrank: this build does not support encrypted dotenv import");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_init() -> ExitCode {
    eprintln!("gschrank: this build does not support secure vault initialization on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_status() -> ExitCode {
    eprintln!("gschrank: this build does not support encrypted diagnostics on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_doctor() -> ExitCode {
    eprintln!("gschrank: this build does not support encrypted diagnostics on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_recovery_list() -> ExitCode {
    eprintln!("gschrank: this build does not support vault recovery on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_restore(_source: PathBuf) -> ExitCode {
    eprintln!("gschrank: this build does not support vault restore on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_rebuild() -> ExitCode {
    eprintln!("gschrank: this build does not support fresh-vault rebuild on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_reset(_shell_wrapper: bool) -> ExitCode {
    eprintln!("gschrank: this build does not support recoverable vault reset on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_full_purge(_shell_wrapper: bool) -> ExitCode {
    eprintln!("gschrank: this build does not support destructive vault purge on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_shell_uninstall(_shell_wrapper: bool) -> ExitCode {
    eprintln!("gschrank: this build does not support Zsh integration removal on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_recovery_restore(_bundle_id: RecoveryBundleId) -> ExitCode {
    eprintln!("gschrank: this build does not support vault recovery on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_recovery_purge(_bundle_id: RecoveryBundleId) -> ExitCode {
    eprintln!("gschrank: this build does not support vault recovery on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_backup(_destination: PathBuf) -> ExitCode {
    eprintln!("gschrank: this build does not support encrypted backups on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_profile(_command: ProfileCommand) -> ExitCode {
    eprintln!("gschrank: this build does not support encrypted profiles on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_set(
    _profile: &ProfileName,
    _variable: EnvironmentName,
    _input: SecretInputMode,
) -> ExitCode {
    eprintln!("gschrank: this build does not support encrypted profiles on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_remove(_profile: &ProfileName, _variable: &EnvironmentName) -> ExitCode {
    eprintln!("gschrank: this build does not support encrypted profiles on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_startup(_command: StartupCommand) -> ExitCode {
    eprintln!("gschrank: this build does not support Zsh startup configuration on this platform");
    ExitCode::from(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_the_available_exact_grammar() {
        assert!(matches!(parse(&[]), Ok(Command::Help)));
        assert!(matches!(parse(&["init".into()]), Ok(Command::Init)));
        assert!(matches!(parse(&["status".into()]), Ok(Command::Status)));
        assert!(matches!(parse(&["doctor".into()]), Ok(Command::Doctor)));
        assert!(matches!(parse(&["--version".into()]), Ok(Command::Version)));
        assert!(matches!(
            parse(&["profile".into(), "list".into()]),
            Ok(Command::Profile(ProfileCommand::List))
        ));
        assert!(matches!(
            parse(&["profile".into(), "create".into(), "dev.local".into()]),
            Ok(Command::Profile(ProfileCommand::Create(_)))
        ));
        assert!(matches!(
            parse(&[
                "profile".into(),
                "rename".into(),
                "dev".into(),
                "work".into()
            ]),
            Ok(Command::Profile(ProfileCommand::Rename { .. }))
        ));
        assert!(matches!(
            parse(&["set".into(), "dev".into(), "API_TOKEN".into()]),
            Ok(Command::Set {
                input: SecretInputMode::HiddenTerminal,
                ..
            })
        ));
        assert!(matches!(
            parse(&[
                "set".into(),
                "dev".into(),
                "API_TOKEN".into(),
                "--stdin".into()
            ]),
            Ok(Command::Set {
                input: SecretInputMode::Stdin,
                ..
            })
        ));
        assert!(matches!(
            parse(&["remove".into(), "dev".into(), "API_TOKEN".into()]),
            Ok(Command::Remove { .. })
        ));
        assert!(matches!(
            parse(&["load".into(), "dev".into()]),
            Ok(Command::ShellParent(ShellParentCommand::Load(_)))
        ));
        assert!(matches!(
            parse(&["reload".into()]),
            Ok(Command::ShellParent(ShellParentCommand::Reload))
        ));
        assert!(matches!(
            parse(&["unload".into()]),
            Ok(Command::ShellParent(ShellParentCommand::Unload))
        ));
        assert!(matches!(
            parse(&["__shell-init".into(), "zsh".into(), "1".into()]),
            Ok(Command::ShellInit { shortcut: false })
        ));
        assert!(matches!(
            parse(&[
                "__emit-zsh".into(),
                "1".into(),
                "startup".into(),
                "load".into(),
                "--".into(),
                "dev".into(),
            ]),
            Ok(Command::EmitZsh {
                context: OperationContext::AutomaticStartup,
                operation: EmitOperation::Load(_),
            })
        ));
        assert!(parse(&["init".into(), "extra".into()]).is_err());
        assert!(parse(&["status".into(), "extra".into()]).is_err());
        assert!(parse(&["doctor".into(), "extra".into()]).is_err());
        assert!(parse(&["profile".into()]).is_err());
        assert!(parse(&["profile".into(), "create".into(), "NOT VALID".into()]).is_err());
        assert!(
            parse(&[
                "set".into(),
                "dev".into(),
                "API_TOKEN".into(),
                "secret-positionally".into()
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "__emit-zsh".into(),
                "1".into(),
                "startup".into(),
                "reload".into(),
            ])
            .is_err()
        );
        assert!(!HELP.contains("__emit-zsh"));
        assert!(!HELP.contains("__shell-init"));
    }

    #[test]
    fn parses_only_the_exact_restore_and_recovery_grammar() {
        let bundle_id = "01010101010101010101010101010101";
        assert!(matches!(
            parse(&["restore".into(), "/tmp/vault.backup".into()]),
            Ok(Command::Restore(_))
        ));
        assert!(matches!(
            parse(&["recovery".into(), "list".into()]),
            Ok(Command::RecoveryList)
        ));
        assert!(matches!(
            parse(&["recovery".into(), "restore".into(), bundle_id.into()]),
            Ok(Command::RecoveryRestore(_))
        ));
        assert!(matches!(
            parse(&["recovery".into(), "purge".into(), bundle_id.into()]),
            Ok(Command::RecoveryPurge(_))
        ));
        assert!(parse(&["restore".into()]).is_err());
        assert!(parse(&["restore".into(), "/tmp/a".into(), "extra".into()]).is_err());
        assert!(parse(&["recovery".into()]).is_err());
        assert!(parse(&["recovery".into(), "list".into(), "extra".into()]).is_err());
        assert!(parse(&["recovery".into(), "restore".into(), "invalid-id".into()]).is_err());
        assert!(parse(&["recovery".into(), "purge".into(), "invalid-id".into()]).is_err());
    }

    #[test]
    fn parses_only_the_exact_public_and_private_reset_grammar() {
        assert!(matches!(
            parse(&["reset".into()]),
            Ok(Command::Reset {
                shell_wrapper: false
            })
        ));
        assert!(matches!(
            parse(&["__reset-from-zsh".into()]),
            Ok(Command::Reset {
                shell_wrapper: true
            })
        ));
        assert!(parse(&["reset".into(), "--force".into()]).is_err());
        assert!(parse(&["__reset-from-zsh".into(), "extra".into()]).is_err());
        assert!(!HELP.contains("__reset-from-zsh"));
    }

    #[test]
    fn parses_only_the_exact_public_and_private_full_purge_grammar() {
        assert!(matches!(
            parse(&["purge".into()]),
            Ok(Command::Purge {
                shell_wrapper: false
            })
        ));
        assert!(matches!(
            parse(&["__purge-from-zsh".into()]),
            Ok(Command::Purge {
                shell_wrapper: true
            })
        ));
        assert!(parse(&["purge".into(), "--force".into()]).is_err());
        assert!(parse(&["__purge-from-zsh".into(), "extra".into()]).is_err());
        assert!(!HELP.contains("__purge-from-zsh"));
    }

    #[test]
    fn parses_only_the_exact_public_and_private_shell_uninstall_grammar() {
        assert!(matches!(
            parse(&["shell".into(), "uninstall".into()]),
            Ok(Command::ShellUninstall {
                shell_wrapper: false
            })
        ));
        assert!(matches!(
            parse(&["__shell-uninstall-from-zsh".into()]),
            Ok(Command::ShellUninstall {
                shell_wrapper: true
            })
        ));
        assert!(parse(&["shell".into()]).is_err());
        assert!(parse(&["shell".into(), "uninstall".into(), "extra".into()]).is_err());
        assert!(parse(&["__shell-uninstall-from-zsh".into(), "extra".into()]).is_err());
        assert!(!HELP.contains("__shell-uninstall-from-zsh"));
    }

    #[test]
    fn shell_uninstall_output_distinguishes_wrapper_cleanup() {
        let direct = render_shell_uninstall_success(false);
        assert!(direct.contains("current shell was not changed"));
        assert!(direct.contains("encrypted vault"));
        assert!(!render_shell_uninstall_success(true).contains("current shell was not changed"));
    }

    #[test]
    fn parses_only_the_exact_rebuild_grammar() {
        assert!(matches!(parse(&["rebuild".into()]), Ok(Command::Rebuild)));
        assert!(parse(&["rebuild".into(), "--force".into()]).is_err());
    }

    #[test]
    fn parses_only_the_exact_backup_grammar() {
        assert!(matches!(
            parse(&["backup".into(), "/tmp/vault.backup".into()]),
            Ok(Command::Backup(_))
        ));
        assert!(parse(&["backup".into()]).is_err());
        assert!(parse(&["backup".into(), "/tmp/vault.backup".into(), "extra".into()]).is_err());
    }

    #[test]
    fn parses_the_exact_guided_configuration_grammar() {
        assert!(matches!(
            parse(&["config".into()]),
            Ok(Command::Config { rc_file: None })
        ));
        assert!(matches!(
            parse(&[
                "config".into(),
                "--rc-file".into(),
                "/tmp/custom-zdot/.zshrc".into()
            ]),
            Ok(Command::Config { rc_file: Some(_) })
        ));
        assert!(parse(&["config".into(), "--rc-file".into()]).is_err());
        assert!(parse(&["config".into(), "--other".into(), "value".into()]).is_err());
    }

    #[test]
    fn parses_the_exact_stdin_only_dotenv_import_grammar() {
        assert!(matches!(
            parse(&["import".into(), "dotenv".into(), "dev".into()]),
            Ok(Command::Import {
                options: ImportOptions {
                    dry_run: false,
                    replace_existing: false,
                },
                ..
            })
        ));
        for flags in [
            ["--dry-run", "--replace-existing"],
            ["--replace-existing", "--dry-run"],
        ] {
            assert!(matches!(
                parse(&[
                    "import".into(),
                    "dotenv".into(),
                    "dev".into(),
                    flags[0].into(),
                    flags[1].into(),
                ]),
                Ok(Command::Import {
                    options: ImportOptions {
                        dry_run: true,
                        replace_existing: true,
                    },
                    ..
                })
            ));
        }
        assert!(
            parse(&[
                "import".into(),
                "dotenv".into(),
                "dev".into(),
                "--stdin".into()
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "import".into(),
                "dotenv".into(),
                "dev".into(),
                ".env".into()
            ])
            .is_err()
        );
        assert!(parse(&["import".into(), "dotenv".into()]).is_err());
    }

    #[test]
    fn import_rendering_contains_names_and_counts_but_no_value_fields() {
        let profile = ProfileName::new("dev").unwrap();
        let output = render_import_outcome(
            &profile,
            ImportOutcome::Imported(crate::profiles::ImportReceipt {
                plan: crate::domain::ImportPlan {
                    created: vec![EnvironmentName::new("ADDED").unwrap()],
                    collisions: vec![EnvironmentName::new("REPLACED").unwrap()],
                },
            }),
        );
        assert!(output.contains("Imported 2 variable(s)"));
        assert!(output.contains("ADDED"));
        assert!(output.contains("REPLACED"));
        assert!(!output.contains("value"));
        assert!(!output.contains("CANARY"));
    }

    #[test]
    fn backup_success_reports_only_safe_revision_metadata() {
        let output = render_backup_success(BackupReceipt { revision: 42 });
        assert_eq!(
            output,
            "Created an encrypted vault backup at revision 42.\n"
        );
        assert!(!output.contains("CANARY"));
        assert!(!output.contains("key"));
        assert!(!output.contains("value"));
    }

    #[test]
    fn restore_success_reports_only_revision_and_recovery_identifier() {
        let output = render_restore_success(RestoreReceipt {
            revision: 7,
            displaced_to: Some(RecoveryBundleId::from_bytes([0x0a; 16])),
        });
        assert!(output.contains("revision 7"));
        assert!(output.contains("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"));
        assert!(!output.contains("profile"));
        assert!(!output.contains("TOKEN"));
        assert!(!output.contains("CANARY"));
    }

    #[test]
    fn reset_success_reports_only_safe_recovery_metadata_and_shell_guidance() {
        let receipt = ResetReceipt {
            vault_id: crate::VaultId::from_bytes([1; 16]),
            key_id: crate::KeyId::from_bytes([2; 16]),
            recovery_bundle: RecoveryBundleId::from_bytes([3; 16]),
        };
        let direct = render_reset_success(receipt, false);
        assert!(direct.contains("03030303030303030303030303030303"));
        assert!(direct.contains("current shell was not changed"));
        assert!(!direct.contains("TOKEN"));
        assert!(!direct.contains("CANARY"));

        let wrapped = render_reset_success(receipt, true);
        assert!(!wrapped.contains("current shell was not changed"));
    }

    #[test]
    fn rebuild_success_reports_only_safe_recovery_and_shell_metadata() {
        let output = render_rebuild_success(RebuildReceipt {
            vault_id: crate::VaultId::from_bytes([1; 16]),
            key_id: crate::KeyId::from_bytes([2; 16]),
            recovery_bundle: RecoveryBundleId::from_bytes([3; 16]),
        });
        assert!(output.contains("revision 0"));
        assert!(output.contains("03030303030303030303030303030303"));
        assert!(output.contains("Existing shells keep"));
        assert!(!output.contains("TOKEN"));
        assert!(!output.contains("CANARY"));
    }

    #[test]
    fn recovery_purge_success_reports_only_safe_counts_and_identifier() {
        let output = render_recovery_purge_success(RecoveryPurgeReceipt {
            bundle_id: RecoveryBundleId::from_bytes([3; 16]),
            retired_key_count: 1,
            retained_key_count: 2,
        });
        assert!(output.contains("03030303030303030303030303030303"));
        assert!(output.contains("Retired Keychain items: 1"));
        assert!(output.contains("Retained shared Keychain items: 2"));
        assert!(!output.contains("TOKEN"));
        assert!(!output.contains("CANARY"));
    }

    #[test]
    fn full_purge_success_reports_safe_counts_and_current_shell_guidance() {
        let receipt = FullPurgeReceipt {
            retired_key_count: 2,
            unauthenticated_artifact_count: 1,
        };
        let direct = render_full_purge_success(receipt, false);
        assert!(direct.contains("Retired Keychain items: 2"));
        assert!(direct.contains("without guessing keys: 1"));
        assert!(direct.contains("current shell was not changed"));
        assert!(direct.contains("does not claim secure erasure"));
        assert!(!direct.contains("TOKEN"));
        assert!(!direct.contains("CANARY"));

        let wrapped = render_full_purge_success(receipt, true);
        assert!(!wrapped.contains("current shell was not changed"));
    }

    #[test]
    fn parses_the_exact_startup_configuration_grammar() {
        assert!(matches!(
            parse(&["startup".into(), "set".into(), "dev".into()]),
            Ok(Command::Startup(StartupCommand::Set(_)))
        ));
        assert!(matches!(
            parse(&["startup".into(), "off".into()]),
            Ok(Command::Startup(StartupCommand::Off))
        ));
        assert!(parse(&["startup".into()]).is_err());
        assert!(parse(&["startup".into(), "set".into()]).is_err());
        assert!(parse(&["startup".into(), "off".into(), "extra".into()]).is_err());
    }

    #[test]
    fn profile_rendering_contains_names_but_no_value_fields() {
        let inspection = ProfileInspection {
            profile: ProfileName::new("dev").unwrap(),
            variables: vec![
                crate::EnvironmentName::new("API_TOKEN").unwrap(),
                crate::EnvironmentName::new("DATABASE_URL").unwrap(),
            ],
        };
        assert_eq!(
            render_profile_success(ProfileSuccess::Inspected(inspection)),
            "dev\nAPI_TOKEN\nDATABASE_URL\n"
        );
        assert_eq!(
            render_profile_success(ProfileSuccess::Listed(vec![
                ProfileName::new("dev").unwrap(),
                ProfileName::new("work").unwrap(),
            ])),
            "dev\nwork\n"
        );
        assert_eq!(
            render_profile_success(ProfileSuccess::Set {
                profile: ProfileName::new("dev").unwrap(),
                variable: EnvironmentName::new("API_TOKEN").unwrap(),
                mutation: Mutation::Updated,
            }),
            "Updated variable 'API_TOKEN' in profile 'dev'.\n"
        );
        assert_eq!(
            render_profile_success(ProfileSuccess::Removed {
                profile: ProfileName::new("dev").unwrap(),
                variable: EnvironmentName::new("API_TOKEN").unwrap(),
            }),
            "Removed variable 'API_TOKEN' from profile 'dev'.\n"
        );
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use std::{
            fs,
            os::unix::fs::PermissionsExt,
            path::PathBuf,
            sync::atomic::{AtomicU64, Ordering},
        };

        use super::*;
        use crate::{
            init::Initializer,
            testing::{MemoryKeyProvider, MemoryVaultStore, ReplacementFault},
        };

        static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

        struct TestDirectory(PathBuf);

        impl TestDirectory {
            fn new() -> Self {
                let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = std::env::temp_dir().join(format!(
                    "gschrank-cli-startup-test-{}-{id}",
                    std::process::id()
                ));
                fs::create_dir(&root).unwrap();
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
                Self(root)
            }

            fn editor(&self) -> ZshConfigEditor {
                ZshConfigEditor::at_path(self.0.join(".zshrc"))
            }

            fn paths(&self) -> MacOsPaths {
                MacOsPaths::at_data_directory(self.0.join("data"))
            }
        }

        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn initialized() -> (MemoryKeyProvider, MemoryVaultStore) {
            let keys = MemoryKeyProvider::new();
            let store = MemoryVaultStore::new();
            Initializer::new(&keys, &store)
                .initialize(InteractionPolicy::FailFast)
                .unwrap();
            (keys, store)
        }

        fn install_startup(editor: &ZshConfigEditor, profile: &ProfileName) {
            let configuration = StartupConfiguration::new(Some(profile.clone()), false);
            let block = ZshEmitter::emit_managed_block(configuration);
            editor.configure(&block).unwrap();
        }

        #[test]
        fn profile_rename_updates_startup_and_delete_guards_the_configured_profile() {
            let test = TestDirectory::new();
            let editor = test.editor();
            let (keys, store) = initialized();
            let operations = ProfileOperations::new(&keys, &store);
            let old = ProfileName::new("work").unwrap();
            let new = ProfileName::new("office").unwrap();
            operations
                .create(old.clone(), InteractionPolicy::FailFast)
                .unwrap();
            install_startup(&editor, &old);

            rename_profile_and_startup_using(
                &editor,
                &operations,
                &old,
                new.clone(),
                InteractionPolicy::FailFast,
            )
            .unwrap();
            assert_eq!(
                operations.list(InteractionPolicy::FailFast).unwrap(),
                vec![new.clone()]
            );
            assert_eq!(
                editor
                    .inspect()
                    .unwrap()
                    .configuration()
                    .and_then(StartupConfiguration::profile),
                Some(&new)
            );

            assert!(matches!(
                delete_profile_with_startup_guard_using(
                    &editor,
                    &operations,
                    &new,
                    InteractionPolicy::FailFast,
                ),
                Err(ProfileCommandError::ConfiguredStartupProfile)
            ));
            assert_eq!(
                operations.list(InteractionPolicy::FailFast).unwrap(),
                vec![new.clone()]
            );

            let off = ZshEmitter::emit_managed_block(StartupConfiguration::new(None, false));
            editor.configure(&off).unwrap();
            delete_profile_with_startup_guard_using(
                &editor,
                &operations,
                &new,
                InteractionPolicy::FailFast,
            )
            .unwrap();
            assert!(
                operations
                    .list(InteractionPolicy::FailFast)
                    .unwrap()
                    .is_empty()
            );
        }

        #[test]
        fn failed_vault_rename_restores_the_previous_startup_reference() {
            let test = TestDirectory::new();
            let editor = test.editor();
            let (keys, store) = initialized();
            let operations = ProfileOperations::new(&keys, &store);
            let old = ProfileName::new("work").unwrap();
            let new = ProfileName::new("office").unwrap();
            operations
                .create(old.clone(), InteractionPolicy::FailFast)
                .unwrap();
            install_startup(&editor, &old);
            store.fail_next_replacement(ReplacementFault::NotCommitted);

            assert!(matches!(
                rename_profile_and_startup_using(
                    &editor,
                    &operations,
                    &old,
                    new,
                    InteractionPolicy::FailFast,
                ),
                Err(ProfileCommandError::Profile(
                    ProfileOperationError::CommitNotCompleted
                ))
            ));
            assert_eq!(
                editor
                    .inspect()
                    .unwrap()
                    .configuration()
                    .and_then(StartupConfiguration::profile),
                Some(&old)
            );
            assert_eq!(
                operations.list(InteractionPolicy::FailFast).unwrap(),
                vec![old]
            );
        }

        #[test]
        fn startup_success_output_distinguishes_edits_from_noops() {
            let profile = ProfileName::new("work").unwrap();
            let changed = StartupSuccess {
                edit: ShellConfigEdit::Installed,
                configuration: StartupConfiguration::new(Some(profile.clone()), true),
                shortcut_conflict: false,
            };
            assert!(render_startup_success(&changed).contains("open a new shell"));

            let unchanged = StartupSuccess {
                edit: ShellConfigEdit::Unchanged,
                configuration: StartupConfiguration::new(Some(profile), true),
                shortcut_conflict: false,
            };
            assert!(!render_startup_success(&unchanged).contains("open a new shell"));
        }

        #[test]
        fn reset_preparation_turns_off_an_existing_startup_profile_without_removing_integration() {
            let test = TestDirectory::new();
            let editor = test.editor();
            let profile = ProfileName::new("work").unwrap();
            install_startup(&editor, &profile);
            let paths = test.paths();
            let resolved = ResolvedZshConfig {
                editor,
                saved: None,
                preferences: ShellPreferenceStore::new(paths.data_directory().to_owned()),
            };

            disable_startup_for_reset(&resolved).unwrap();

            let state = resolved.editor.inspect().unwrap();
            let configuration = state.configuration().unwrap();
            assert!(configuration.profile().is_none());
            assert!(!configuration.shortcut());
            let saved = resolved.preferences.read().unwrap().unwrap();
            assert_eq!(saved.rc_file(), resolved.editor.path());
        }

        #[test]
        fn shell_uninstall_removes_managed_integration_and_saved_preferences_idempotently() {
            let test = TestDirectory::new();
            let editor = test.editor();
            let profile = ProfileName::new("work").unwrap();
            install_startup(&editor, &profile);
            let paths = test.paths();
            let preferences = ShellPreferenceStore::new(paths.data_directory().to_owned());
            preferences
                .write(&ShellPreferences::new(editor.path().to_owned(), false).unwrap())
                .unwrap();
            let resolved = ResolvedZshConfig {
                editor,
                saved: preferences.read().unwrap(),
                preferences,
            };

            remove_persistent_shell_integration(&resolved).unwrap();

            assert_eq!(
                resolved.editor.inspect().unwrap(),
                ShellIntegrationState::Absent
            );
            assert_eq!(resolved.preferences.read().unwrap(), None);
            remove_persistent_shell_integration(&resolved).unwrap();
        }

        fn installed_shell() -> ZshDiagnostic {
            ZshDiagnostic {
                integration: ShellIntegrationState::Installed(StartupConfiguration::new(
                    None, false,
                )),
                shortcut: ShortcutDiagnostic::Disabled,
                canonical_conflict: false,
            }
        }

        fn clear_recovery() -> RecoveryOverview {
            RecoveryOverview {
                initialization_pending: false,
                rebuild_pending: false,
                bundle_count: 0,
                purge_pending_count: 0,
                full_purge_pending: false,
            }
        }

        #[test]
        fn recovery_list_renders_only_safe_metadata_and_authentication_state() {
            use crate::{
                KeyId, VaultId,
                recovery::{RecoveryAuthentication, RecoveryInspection},
                vault_store::{RecoveryBundleId, RecoveryReason},
            };

            let output = render_recovery_list(&RecoveryList {
                bundles: vec![RecoveryInspection {
                    id: RecoveryBundleId::from_bytes([1; 16]),
                    created_at_unix_seconds: 1_765_000_000,
                    reason: RecoveryReason::Restore,
                    vault_id: Some(VaultId::from_bytes([2; 16])),
                    key_id: Some(KeyId::from_bytes([3; 16])),
                    authentication: RecoveryAuthentication::Authenticated,
                }],
                purge_pending: vec![RecoveryBundleId::from_bytes([4; 16])],
                full_purge_pending: false,
            });

            assert!(output.contains("01010101010101010101010101010101"));
            assert!(output.contains("Reason: restore"));
            assert!(output.contains("Authentication: authenticated"));
            assert!(output.contains("Recovery purges pending:"));
            assert!(output.contains("04040404040404040404040404040404"));
            assert!(!output.contains("profile"));
            assert!(!output.contains("TOKEN"));
            assert!(!output.contains("CANARY-super-secret"));
        }

        #[test]
        fn status_renders_authenticated_names_but_never_secret_values() {
            let report = StatusReport {
                vault: Ok(VaultInspection {
                    revision: 7,
                    profiles: vec![ProfileInspection {
                        profile: ProfileName::new("dev").unwrap(),
                        variables: vec![EnvironmentName::new("API_TOKEN").unwrap()],
                    }],
                }),
                recovery: Ok(clear_recovery()),
                shell: Ok(installed_shell()),
                current_shell: ManagedState::from_metadata(
                    Some("1"),
                    Some("dev"),
                    Some("API_TOKEN"),
                ),
            };

            let output = render_status(&report);
            assert!(output.contains("Status: ready"));
            assert!(output.contains("revision 7"));
            assert!(output.contains("dev"));
            assert!(output.contains("API_TOKEN"));
            assert!(!output.contains("CANARY-super-secret"));
            assert_eq!(report.exit_code(), 0);
        }

        #[test]
        fn failed_status_never_renders_cached_vault_names() {
            let report = StatusReport {
                vault: Err(ProfileOperationError::VaultKeyMissing),
                recovery: Ok(clear_recovery()),
                shell: Ok(installed_shell()),
                current_shell: Ok(ManagedState::empty()),
            };
            let output = render_status(&report);
            assert!(output.contains("Status: frozen"));
            assert!(!output.contains("Profiles:"));
            assert!(!output.contains("dev"));
            assert!(!output.contains("API_TOKEN"));
            assert_eq!(report.exit_code(), 12);
        }

        #[test]
        fn diagnostics_distinguish_pending_initialization_from_uninitialized_state() {
            let report = DoctorReport {
                vault: Err(ProfileOperationError::NotInitialized),
                recovery: Ok(RecoveryOverview {
                    initialization_pending: true,
                    rebuild_pending: false,
                    bundle_count: 2,
                    purge_pending_count: 0,
                    full_purge_pending: false,
                }),
                shell: Ok(installed_shell()),
                current_shell: Ok(ManagedState::empty()),
            };

            let output = render_doctor(&report);
            assert!(output.contains("Doctor: initialization pending"));
            assert!(output.contains("Initialization candidate: present"));
            assert!(output.contains("Recovery bundles: 2"));
            assert!(output.contains("run 'gschrank init'"));
            assert_eq!(report.exit_code(), 14);
        }

        #[test]
        fn diagnostics_make_an_interrupted_rebuild_actionable_without_names() {
            let report = DoctorReport {
                vault: Ok(VaultReadiness { revision: 7 }),
                recovery: Ok(RecoveryOverview {
                    initialization_pending: false,
                    rebuild_pending: true,
                    bundle_count: 1,
                    purge_pending_count: 0,
                    full_purge_pending: false,
                }),
                shell: Ok(installed_shell()),
                current_shell: Ok(ManagedState::empty()),
            };

            let output = render_doctor(&report);
            assert!(output.contains("Doctor: rebuild pending"));
            assert!(output.contains("Rebuild candidate: present"));
            assert!(output.contains("run 'gschrank rebuild'"));
            assert!(!output.contains("TOKEN"));
            assert_eq!(report.exit_code(), 14);
        }

        #[test]
        fn diagnostics_make_an_interrupted_recovery_purge_actionable() {
            let report = DoctorReport {
                vault: Ok(VaultReadiness { revision: 7 }),
                recovery: Ok(RecoveryOverview {
                    initialization_pending: false,
                    rebuild_pending: false,
                    bundle_count: 0,
                    purge_pending_count: 1,
                    full_purge_pending: false,
                }),
                shell: Ok(installed_shell()),
                current_shell: Ok(ManagedState::empty()),
            };

            let output = render_doctor(&report);
            assert!(output.contains("Doctor: recovery purge pending"));
            assert!(output.contains("Recovery purges pending: 1"));
            assert!(output.contains("gschrank recovery list"));
            assert!(!output.contains("TOKEN"));
            assert_eq!(report.exit_code(), 14);
        }

        #[test]
        fn diagnostics_make_an_interrupted_full_purge_actionable() {
            let report = DoctorReport {
                vault: Err(ProfileOperationError::Store(
                    crate::vault_store::VaultStoreError::new(
                        crate::vault_store::VaultStoreErrorKind::Conflict,
                    ),
                )),
                recovery: Ok(RecoveryOverview {
                    initialization_pending: false,
                    rebuild_pending: false,
                    bundle_count: 0,
                    purge_pending_count: 0,
                    full_purge_pending: true,
                }),
                shell: Ok(ZshDiagnostic {
                    integration: ShellIntegrationState::Absent,
                    shortcut: ShortcutDiagnostic::Disabled,
                    canonical_conflict: false,
                }),
                current_shell: Ok(ManagedState::empty()),
            };

            let output = render_doctor(&report);
            assert!(output.contains("Doctor: full purge pending"));
            assert!(output.contains("Full purge pending: yes"));
            assert!(output.contains("run 'gschrank purge'"));
            assert!(!output.contains("TOKEN"));
            assert_eq!(report.exit_code(), 14);
        }

        #[test]
        fn doctor_is_name_free_and_maps_lifecycle_failures_to_stable_exits() {
            let healthy = DoctorReport {
                vault: Ok(VaultReadiness { revision: 9 }),
                recovery: Ok(clear_recovery()),
                shell: Ok(installed_shell()),
                current_shell: ManagedState::from_metadata(
                    Some("1"),
                    Some("private-profile"),
                    Some("PRIVATE_TOKEN"),
                ),
            };
            let output = render_doctor(&healthy);
            assert!(output.contains("Doctor: healthy"));
            assert!(output.contains("Revision: 9"));
            assert!(output.contains("valid active metadata"));
            assert!(output.contains("count 1"));
            assert!(!output.contains("private-profile"));
            assert!(!output.contains("PRIVATE_TOKEN"));
            assert!(!output.contains("CANARY-super-secret"));
            assert_eq!(healthy.exit_code(), 0);

            let not_initialized = DoctorReport {
                vault: Err(ProfileOperationError::NotInitialized),
                recovery: Ok(clear_recovery()),
                shell: Ok(installed_shell()),
                current_shell: Ok(ManagedState::empty()),
            };
            assert!(render_doctor(&not_initialized).contains("Doctor: not initialized"));
            assert_eq!(not_initialized.exit_code(), 10);

            let frozen = DoctorReport {
                vault: Err(ProfileOperationError::VaultKeyMissing),
                recovery: Ok(clear_recovery()),
                shell: Ok(installed_shell()),
                current_shell: Ok(ManagedState::empty()),
            };
            let output = render_doctor(&frozen);
            assert!(output.contains("Doctor: frozen"));
            assert!(output.contains("Keychain item: missing"));
            assert_eq!(frozen.exit_code(), 12);
        }

        #[test]
        fn doctor_requires_installed_canonical_shell_integration_and_valid_metadata() {
            let absent = DoctorReport {
                vault: Ok(VaultReadiness { revision: 0 }),
                recovery: Ok(clear_recovery()),
                shell: Ok(ZshDiagnostic {
                    integration: ShellIntegrationState::Absent,
                    shortcut: ShortcutDiagnostic::Disabled,
                    canonical_conflict: false,
                }),
                current_shell: Ok(ManagedState::empty()),
            };
            assert_eq!(absent.exit_code(), 14);
            assert!(render_doctor(&absent).contains("run 'gschrank config'"));

            let conflict = DoctorReport {
                vault: Ok(VaultReadiness { revision: 0 }),
                recovery: Ok(clear_recovery()),
                shell: Ok(ZshDiagnostic {
                    canonical_conflict: true,
                    ..installed_shell()
                }),
                current_shell: Ok(ManagedState::empty()),
            };
            assert_eq!(conflict.exit_code(), 14);
            assert!(render_doctor(&conflict).contains("unmanaged 'gschrank'"));

            let invalid_metadata = DoctorReport {
                vault: Ok(VaultReadiness { revision: 0 }),
                recovery: Ok(clear_recovery()),
                shell: Ok(installed_shell()),
                current_shell: Err(ManagedStateError::Incomplete),
            };
            assert_eq!(invalid_metadata.exit_code(), 14);
            assert!(render_doctor(&invalid_metadata).contains("fresh Zsh session"));
        }

        #[test]
        fn saved_rc_file_is_reused_and_conflicting_overrides_fail_before_editing() {
            let test = TestDirectory::new();
            let paths = test.paths();
            let rc_file = test.0.join("custom.zshrc");
            let selected = resolve_zsh_config(&paths, Some(rc_file.clone())).unwrap();
            assert_eq!(selected.editor.path(), rc_file);
            selected.remember(false).unwrap();

            let reused = resolve_zsh_config(&paths, None).unwrap();
            assert_eq!(reused.editor.path(), rc_file);
            assert!(!reused.shortcut_default());
            assert!(matches!(
                resolve_zsh_config(&paths, Some(test.0.join("other.zshrc"))),
                Err(ShellConfigurationError::DifferentRcFile)
            ));
            assert!(!test.0.join("other.zshrc").exists());
        }
    }
}
