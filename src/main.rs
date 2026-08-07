#![forbid(unsafe_code)]

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("gschrank {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") | None => {
            println!(
                "gschrank {}\n\nEncrypted environment profiles for your shell.\n\n\
                 The portable encrypted-vault core is implemented. Keychain, filesystem,\n\
                 and Zsh commands are the next development milestone.",
                env!("CARGO_PKG_VERSION")
            );
            ExitCode::SUCCESS
        }
        Some(_) => {
            eprintln!(
                "gschrank: this command is not available in the current development milestone"
            );
            ExitCode::from(1)
        }
    }
}
