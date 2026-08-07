#![forbid(unsafe_code)]

use std::{ffi::OsString, io::IsTerminal, process::ExitCode};

use crate::{
    DomainError, ProfileName,
    init::{InitOutcome, Initializer},
    key_provider::InteractionPolicy,
    profiles::{ProfileInspection, ProfileOperations},
};

#[cfg(target_os = "macos")]
use crate::platform::macos::{LocalVaultStore, MacOsKeychainProvider, MacOsPaths};

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
  gschrank --help
  gschrank --version

Commands:
  init       Create an empty encrypted vault, or validate the existing vault
  profile    Create, rename, delete, list, or inspect profiles

Only macOS is supported in this development milestone. Secret-value entry and
Zsh integration commands are not implemented yet."
);

enum Command {
    Help,
    Version,
    Init,
    Profile(ProfileCommand),
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
    Renamed { old: ProfileName, new: ProfileName },
    Deleted(ProfileName),
    Listed(Vec<ProfileName>),
    Inspected(ProfileInspection),
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
        _ => Err(ParseError::InvalidGrammar),
    }
}

fn parse_profile_name(argument: &OsString) -> Result<ProfileName, ParseError> {
    let name = argument.to_str().ok_or(ParseError::InvalidGrammar)?;
    ProfileName::new(name).map_err(ParseError::InvalidName)
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
        assert!(parse(&["init".into(), "extra".into()]).is_err());
        assert!(parse(&["profile".into()]).is_err());
        assert!(parse(&["profile".into(), "create".into(), "NOT VALID".into()]).is_err());
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
    }
}
