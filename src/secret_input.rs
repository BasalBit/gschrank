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
    stderr
        .write_all(b"Enter value: ")
        .and_then(|()| stderr.flush())
        .map_err(|_| SecretInputError::IoFailure)?;
    let input = read_hidden_stdin(MAX_VALUE_BYTES).map_err(|error| match error {
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
    use std::io::{self, Cursor};

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
}
