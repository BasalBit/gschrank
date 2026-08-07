#![forbid(unsafe_code)]

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    gschrank::run_cli(env::args_os().skip(1))
}
