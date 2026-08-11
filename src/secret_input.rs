#![forbid(unsafe_code)]

use std::{error::Error, fmt, io::IsTerminal, io::Read, io::Write};

use zeroize::Zeroizing;

use crate::{DomainError, MAX_VALUE_BYTES, SecretValue};

#[cfg(target_os = "macos")]
use crate::platform::macos::{HiddenInputError, read_hidden_stdin};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretInputMode {
    HiddenTerminal,
    Stdin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretInputError {
    StdinMustNotBeTerminal,
    InteractiveTerminalRequired,
    Interrupted,
    InvalidValue(DomainError),
    IoFailure,
    #[cfg(not(target_os = "macos"))]
    UnsupportedPlatform,
}

impl SecretInputError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::StdinMustNotBeTerminal
            | Self::InteractiveTerminalRequired
            | Self::InvalidValue(_) => 2,
            Self::Interrupted => 130,
            Self::IoFailure => 1,
            #[cfg(not(target_os = "macos"))]
            Self::UnsupportedPlatform => 1,
        }
    }
}

impl fmt::Display for SecretInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StdinMustNotBeTerminal => {
                formatter.write_str("--stdin requires redirected or piped standard input")
            }
            Self::InteractiveTerminalRequired => formatter.write_str(
                "interactive set requires terminal input; use --stdin for a pipe or redirection",
            ),
            Self::Interrupted => formatter.write_str("secret input interrupted"),
            Self::InvalidValue(error) => fmt::Display::fmt(error, formatter),
            Self::IoFailure => formatter.write_str("secret input failed"),
            #[cfg(not(target_os = "macos"))]
            Self::UnsupportedPlatform => {
                formatter.write_str("hidden terminal input is unsupported on this platform")
            }
        }
    }
}

impl Error for SecretInputError {}

pub(crate) fn read_secret(mode: SecretInputMode) -> Result<SecretValue, SecretInputError> {
    match mode {
        SecretInputMode::Stdin => read_stdin_secret(),
        SecretInputMode::HiddenTerminal => read_hidden_terminal_secret(),
    }
}

fn read_stdin_secret() -> Result<SecretValue, SecretInputError> {
    let stdin = std::io::stdin();
    let is_terminal = stdin.is_terminal();
    read_stdin_source(stdin.lock(), is_terminal)
}

fn read_stdin_source(
    reader: impl Read,
    is_terminal: bool,
) -> Result<SecretValue, SecretInputError> {
    if is_terminal {
        return Err(SecretInputError::StdinMustNotBeTerminal);
    }
    read_stream(reader)
}

fn read_stream(reader: impl Read) -> Result<SecretValue, SecretInputError> {
    let limit = u64::try_from(MAX_VALUE_BYTES)
        .expect("maximum value size fits u64")
        .saturating_add(1);
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(MAX_VALUE_BYTES.saturating_add(1))
        .map_err(|_| SecretInputError::IoFailure)?;
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| SecretInputError::IoFailure)?;
    SecretValue::from_zeroizing(bytes).map_err(SecretInputError::InvalidValue)
}

#[cfg(target_os = "macos")]
fn read_hidden_terminal_secret() -> Result<SecretValue, SecretInputError> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(SecretInputError::InteractiveTerminalRequired);
    }

    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let input = read_hidden_stdin(MAX_VALUE_BYTES, || {
        stderr
            .write_all(b"Enter value: ")
            .and_then(|()| stderr.flush())
            .map_err(|_| HiddenInputError::IoFailure)
    })
    .map_err(|error| match error {
        HiddenInputError::NotTerminal => SecretInputError::InteractiveTerminalRequired,
        HiddenInputError::IoFailure => SecretInputError::IoFailure,
        HiddenInputError::Interrupted => SecretInputError::Interrupted,
    });
    let newline = stderr.write_all(b"\n").and_then(|()| stderr.flush());
    match (input, newline) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(_)) => Err(SecretInputError::IoFailure),
        (Ok(input), Ok(())) => {
            SecretValue::from_zeroizing(input).map_err(SecretInputError::InvalidValue)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn read_hidden_terminal_secret() -> Result<SecretValue, SecretInputError> {
    Err(SecretInputError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, BufRead, BufReader, Cursor, Read, Write},
        process::{Command, Stdio},
    };

    use super::*;

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected secret input failure"))
        }
    }

    fn expose(result: Result<SecretValue, SecretInputError>) -> Vec<u8> {
        match result {
            Ok(value) => value.expose().to_vec(),
            Err(error) => panic!("expected valid secret input, got {error}"),
        }
    }

    #[test]
    fn stream_input_preserves_empty_unicode_whitespace_and_newlines_exactly() {
        for input in [
            b"".as_slice(),
            "  ü\n$() `quoted`\t\n".as_bytes(),
            b"trailing-newlines\n\n".as_slice(),
        ] {
            assert!(
                expose(read_stream(Cursor::new(input))) == input,
                "stream secret byte preservation failed"
            );
        }
    }

    #[test]
    fn stream_input_is_bounded_and_reports_only_safe_errors() {
        let oversized = vec![b'X'; MAX_VALUE_BYTES + 1];
        let Err(error) = read_stream(Cursor::new(oversized)) else {
            panic!("oversized input must fail");
        };
        assert_eq!(
            error,
            SecretInputError::InvalidValue(DomainError::ValueLimitExceeded)
        );
        assert_eq!(error.exit_code(), 2);

        let Err(io_error) = read_stream(FailingReader) else {
            panic!("injected I/O failure must fail");
        };
        assert_eq!(io_error, SecretInputError::IoFailure);
        assert!(!io_error.to_string().contains("injected"));
    }

    #[test]
    fn explicit_stdin_rejects_a_terminal_before_reading_it() {
        let Err(error) = read_stdin_source(FailingReader, true) else {
            panic!("terminal stdin must fail");
        };
        assert_eq!(error, SecretInputError::StdinMustNotBeTerminal);
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn stream_input_rejects_nul_and_invalid_utf8_without_echoing_bytes() {
        for input in [vec![b'C', 0, b'Y'], vec![0xff, 0xfe]] {
            let Err(error) = read_stream(Cursor::new(input)) else {
                panic!("invalid value must fail");
            };
            assert_eq!(
                error,
                SecretInputError::InvalidValue(DomainError::InvalidValue)
            );
            assert_eq!(error.to_string(), "value must be UTF-8 without NUL bytes");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stdin_secret_never_enters_process_arguments_or_public_output() {
        let canary = crate::testing::AcceptanceCanary::unique("process");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "secret_input::tests::stdin_process_observation_fixture",
                "--nocapture",
            ])
            .env("GSCHRANK_STDIN_OBSERVATION_FIXTURE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&(canary.value().len() as u64).to_be_bytes())
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(canary.value().as_bytes())
            .unwrap();

        let mut stdout_reader = BufReader::new(child.stdout.take().unwrap());
        let mut stdout = Vec::new();
        loop {
            let mut line = String::new();
            assert_ne!(stdout_reader.read_line(&mut line).unwrap(), 0);
            stdout.extend_from_slice(line.as_bytes());
            if line == "ready\n" {
                break;
            }
        }

        let process = Command::new("/bin/ps")
            .args(["-p", &child.id().to_string(), "-o", "command="])
            .output()
            .unwrap();
        assert!(process.status.success());
        canary.assert_absent("process arguments and title", &process.stdout);
        drop(child.stdin.take());
        stdout_reader.read_to_end(&mut stdout).unwrap();
        let mut stderr = Vec::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        assert!(child.wait().unwrap().success());
        canary.assert_absent("fixture stdout", &stdout);
        canary.assert_absent("fixture stderr", &stderr);
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "subprocess fixture"]
    fn stdin_process_observation_fixture() {
        if std::env::var_os("GSCHRANK_STDIN_OBSERVATION_FIXTURE").is_none() {
            return;
        }
        let mut stdin = std::io::stdin().lock();
        let mut length = [0_u8; 8];
        stdin.read_exact(&mut length).unwrap();
        let value = read_stream((&mut stdin).take(u64::from_be_bytes(length))).unwrap();
        assert!(value.expose().starts_with(b" GSCHRANK_ACCEPTANCE_CANARY_"));
        println!("ready");
        std::io::stdout().flush().unwrap();
        let mut end = [0_u8; 1];
        assert_eq!(stdin.read(&mut end).unwrap(), 0);
    }
}
