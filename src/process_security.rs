#![forbid(unsafe_code)]

use std::{
    ffi::OsString,
    io::{self, Write},
    panic::{self, AssertUnwindSafe},
    process::ExitCode,
};

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreDumpSuppression {
    Active,
    Unavailable,
}

#[cfg(not(target_os = "macos"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoreDumpSuppression {
    NotApplicable,
}

/// Runs the CLI behind process-level crash hardening.
pub fn run(arguments: impl IntoIterator<Item = OsString>) -> ExitCode {
    install_sanitized_panic_hook();
    catch_command(move || {
        let core_dumps = suppress_core_dumps();
        crate::cli::run_cli(arguments, core_dumps)
    })
}

fn install_sanitized_panic_hook() {
    panic::set_hook(Box::new(|_| {
        write_panic_diagnostic(&mut io::stderr().lock());
    }));
}

fn write_panic_diagnostic(writer: &mut impl Write) {
    let _ = writer.write_all(b"gschrank: unexpected internal failure\n");
}

fn catch_command(command: impl FnOnce() -> ExitCode) -> ExitCode {
    match panic::catch_unwind(AssertUnwindSafe(command)) {
        Ok(exit_code) => exit_code,
        Err(payload) => {
            drop(payload);
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "macos")]
fn suppress_core_dumps() -> CoreDumpSuppression {
    if crate::platform::macos::suppress_core_dumps().is_ok() {
        CoreDumpSuppression::Active
    } else {
        CoreDumpSuppression::Unavailable
    }
}

#[cfg(not(target_os = "macos"))]
const fn suppress_core_dumps() -> CoreDumpSuppression {
    CoreDumpSuppression::NotApplicable
}

#[cfg(test)]
mod tests {
    use std::{
        process::Command,
        sync::{Arc, Mutex},
    };

    use super::*;

    struct DropFlag(Arc<Mutex<bool>>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            *self.0.lock().unwrap() = true;
        }
    }

    #[test]
    fn preserves_successful_command_exit_status() {
        assert_eq!(catch_command(|| ExitCode::from(14)), ExitCode::from(14));
    }

    #[test]
    fn panic_boundary_drops_owned_state_and_returns_runtime_failure() {
        let dropped = Arc::new(Mutex::new(false));
        let owned = DropFlag(Arc::clone(&dropped));

        let result = catch_command(|| {
            let _owned = owned;
            panic::resume_unwind(Box::new("CANARY-secret-panic-payload"));
        });

        assert_eq!(result, ExitCode::from(1));
        assert!(*dropped.lock().unwrap());
    }

    #[test]
    fn panic_diagnostic_is_fixed_and_payload_free() {
        let mut diagnostic = Vec::new();
        write_panic_diagnostic(&mut diagnostic);
        assert_eq!(diagnostic, b"gschrank: unexpected internal failure\n");
        assert!(!diagnostic.windows(6).any(|bytes| bytes == b"CANARY"));
    }

    #[test]
    fn installed_hook_hides_the_panic_payload_in_a_subprocess() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "process_security::tests::panic_hook_subprocess_fixture",
                "--nocapture",
            ])
            .env("GSCHRANK_PANIC_HOOK_TEST", "1")
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(
            output
                .stderr
                .windows(b"gschrank: unexpected internal failure".len())
                .any(|bytes| bytes == b"gschrank: unexpected internal failure")
        );
        assert!(!output.stderr.windows(6).any(|bytes| bytes == b"CANARY"));
    }

    #[test]
    #[ignore = "subprocess fixture"]
    fn panic_hook_subprocess_fixture() {
        if std::env::var_os("GSCHRANK_PANIC_HOOK_TEST").is_none() {
            return;
        }
        install_sanitized_panic_hook();
        panic!("CANARY-secret-panic-payload");
    }
}
