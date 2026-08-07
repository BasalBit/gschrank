#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    io::{IsTerminal, Write},
    process::ExitCode,
};

use crate::{
    DomainError, EnvironmentName, Mutation, ProfileName,
    init::{InitOutcome, Initializer},
    key_provider::InteractionPolicy,
    profiles::{ProfileInspection, ProfileOperations},
    secret_input::{SecretInputMode, read_secret},
    set_command::execute_set,
    shell::{ShellEmitter, ZshEmitter},
    shell_transition::{
        ACTIVE_PROFILE_NAME, ENV_PROTOCOL_NAME, MANAGED_KEYS_NAME, ManagedState, ManagedStateError,
        OperationContext, ShellTransition,
    },
};

#[cfg(target_os = "macos")]
use crate::platform::macos::{LocalVaultStore, MacOsKeychainProvider, MacOsPathError, MacOsPaths};

const HELP: &str = concat!(
    "gschrank ",
    env!("CARGO_PKG_VERSION"),
    "

Encrypted environment profiles for your shell.

Usage:
  gschrank init
  gschrank profile create <profile>
  gschrank profile rename <old> <new>
  gschrank profile delete <profile>
  gschrank profile list
  gschrank profile inspect <profile>
  gschrank set <profile> <variable> [--stdin]
  gschrank remove <profile> <variable>
  gschrank load <profile>
  gschrank reload
  gschrank unload
  gschrank --help
  gschrank --version

Commands:
  init       Create an empty encrypted vault, or validate the existing vault
  profile    Create, rename, delete, list, or inspect profiles
  set        Create or update a variable using hidden or explicit stdin input
  remove     Remove a variable from a profile
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
    Init,
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
        Ok(Command::Init) => run_init(),
        Ok(Command::Profile(command)) => run_profile(command),
        Ok(Command::Set {
            profile,
            variable,
            input,
        }) => run_set(&profile, variable, input),
        Ok(Command::Remove { profile, variable }) => run_remove(&profile, &variable),
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
        [argument] if argument == "init" => Ok(Command::Init),
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

    let result = match command {
        ProfileCommand::Create(profile) => {
            let output = profile.clone();
            operations
                .create(profile, interaction)
                .map(|_| ProfileSuccess::Created(output))
        }
        ProfileCommand::Rename { old, new } => {
            let output_old = old.clone();
            let output_new = new.clone();
            operations
                .rename(&old, new, interaction)
                .map(|_| ProfileSuccess::Renamed {
                    old: output_old,
                    new: output_new,
                })
        }
        ProfileCommand::Delete(profile) => operations
            .delete(&profile, interaction)
            .map(|_| ProfileSuccess::Deleted(profile)),
        ProfileCommand::List => operations.list(interaction).map(ProfileSuccess::Listed),
        ProfileCommand::Inspect(profile) => operations
            .inspect(&profile, interaction)
            .map(ProfileSuccess::Inspected),
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
            match authenticated_snapshot(&profile, interaction_for_context(context)) {
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
            match authenticated_snapshot(&profile, interaction_for_context(context)) {
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

#[cfg(target_os = "macos")]
fn interaction_for_context(context: OperationContext) -> InteractionPolicy {
    match context {
        OperationContext::Explicit => interaction_policy(),
        OperationContext::AutomaticStartup => InteractionPolicy::FailFast,
    }
}

#[cfg(not(target_os = "macos"))]
fn run_emit_zsh(_context: OperationContext, _operation: EmitOperation) -> ExitCode {
    eprintln!("gschrank: this build does not support encrypted profiles on this platform");
    ExitCode::from(1)
}

#[cfg(not(target_os = "macos"))]
fn run_init() -> ExitCode {
    eprintln!("gschrank: this build does not support secure vault initialization on this platform");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_the_available_exact_grammar() {
        assert!(matches!(parse(&[]), Ok(Command::Help)));
        assert!(matches!(parse(&["init".into()]), Ok(Command::Init)));
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
}
