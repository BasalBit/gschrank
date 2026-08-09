#![forbid(unsafe_code)]

use std::{env, process::ExitCode};

fn main() -> ExitCode {
    gschrank::run(env::args_os().skip(1))
}
