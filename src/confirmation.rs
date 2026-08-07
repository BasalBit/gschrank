#![forbid(unsafe_code)]

use std::{error::Error, fmt, io::IsTerminal, io::Read, io::Write};

const MAX_CONFIRMATION_BYTES: usize = 64;

/// One explicit typed confirmation selected by portable lifecycle policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TypedConfirmationRequest {
    pub(crate) expected: &'static str,
    pub(crate) action: &'static str,
    pub(crate) warning: &'static str,
}

/// Safe failure categories for an explicit destructive confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfirmationError {
    TerminalRequired,
    Cancelled,
    Rejected,
    InvalidInput,
    IoFailure,
}

impl ConfirmationError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::TerminalRequired | Self::Cancelled | Self::Rejected | Self::InvalidInput => 14,
            Self::IoFailure => 1,
        }
    }
}

impl fmt::Display for ConfirmationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TerminalRequired => "this operation requires an interactive terminal",
            Self::Cancelled => "confirmation was cancelled",
            Self::Rejected => "the typed confirmation did not match; nothing was changed",
            Self::InvalidInput => "the typed confirmation was invalid",
            Self::IoFailure => "the typed confirmation could not be read",
        })
    }
}

impl Error for ConfirmationError {}

/// Injected confirmation mechanism used while lifecycle policy retains its lock.
pub(crate) trait TypedConfirmer {
    fn confirm(&mut self, request: TypedConfirmationRequest) -> Result<(), ConfirmationError>;
}

/// Visible, bounded confirmation input for the production terminal.
pub(crate) struct TerminalTypedConfirmer;

impl TypedConfirmer for TerminalTypedConfirmer {
    fn confirm(&mut self, request: TypedConfirmationRequest) -> Result<(), ConfirmationError> {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(ConfirmationError::TerminalRequired);
        }
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        writeln!(stderr, "{}", request.warning).map_err(|_| ConfirmationError::IoFailure)?;
        write!(
            stderr,
            "Type '{}' to {}: ",
            request.expected, request.action
        )
        .and_then(|()| stderr.flush())
        .map_err(|_| ConfirmationError::IoFailure)?;
        let answer = read_visible_confirmation(std::io::stdin().lock())?;
        validate_typed_confirmation(&answer, request.expected)
    }
}

fn validate_typed_confirmation(answer: &str, expected: &str) -> Result<(), ConfirmationError> {
    if answer == expected {
        Ok(())
    } else {
        Err(ConfirmationError::Rejected)
    }
}

fn read_visible_confirmation(mut input: impl Read) -> Result<String, ConfirmationError> {
    let mut bytes = Vec::with_capacity(16);
    loop {
        let mut byte = [0_u8; 1];
        match input.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Err(ConfirmationError::Cancelled),
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if bytes.len() == MAX_CONFIRMATION_BYTES {
                    return Err(ConfirmationError::InvalidInput);
                }
                bytes.push(byte[0]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                return Err(ConfirmationError::Cancelled);
            }
            Err(_) => return Err(ConfirmationError::IoFailure),
        }
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|_| ConfirmationError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_confirmation_is_exact_bounded_and_value_free_on_failure() {
        assert_eq!(
            read_visible_confirmation(&b"RESTORE\n"[..]).unwrap(),
            "RESTORE"
        );
        assert_eq!(
            read_visible_confirmation(&b"RESTORE\r\n"[..]).unwrap(),
            "RESTORE"
        );
        assert_eq!(
            read_visible_confirmation(&b""[..]).unwrap_err(),
            ConfirmationError::Cancelled
        );
        assert_eq!(
            read_visible_confirmation(vec![b'x'; MAX_CONFIRMATION_BYTES + 1].as_slice())
                .unwrap_err(),
            ConfirmationError::InvalidInput
        );
        assert_eq!(validate_typed_confirmation("RESTORE", "RESTORE"), Ok(()));
        assert_eq!(
            validate_typed_confirmation("restore", "RESTORE"),
            Err(ConfirmationError::Rejected)
        );
    }
}
