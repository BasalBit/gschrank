#![forbid(unsafe_code)]

use std::{ffi::OsString, io::IsTerminal, process::ExitCode};

use crate::{
    init::{InitOutcome, Initializer},
    key_provider::InteractionPolicy,
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
  gschrank --help
  gschrank --version

Commands:
  init    Create an empty encrypted vault, or validate the existing vault

Only macOS is supported in this development milestone. Profile and Zsh
integration commands are not implemented yet."
);

enum Command {
    Help,
    Version,
    Init,
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
        Err(()) => {
            eprintln!("gschrank: invalid command or arguments\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}

fn parse(arguments: &[OsString]) -> Result<Command, ()> {
    match arguments {
        [] => Ok(Command::Help),
        [argument] if argument == "--help" || argument == "-h" => Ok(Command::Help),
        [argument] if argument == "--version" || argument == "-V" => Ok(Command::Version),
        [argument] if argument == "init" => Ok(Command::Init),
        _ => Err(()),
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
    let interaction = if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        InteractionPolicy::AllowPrompt
    } else {
        InteractionPolicy::FailFast
    };

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

#[cfg(not(target_os = "macos"))]
fn run_init() -> ExitCode {
    eprintln!("gschrank: this build does not support secure vault initialization on this platform");
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
        assert!(parse(&["init".into(), "extra".into()]).is_err());
        assert!(parse(&["profile".into()]).is_err());
    }
}
