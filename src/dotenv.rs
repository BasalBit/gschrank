#![forbid(unsafe_code)]

use std::{collections::BTreeMap, error::Error, fmt, io::Read};

use zeroize::Zeroizing;

use crate::{
    DomainError, EnvironmentName, MAX_PROFILE_BYTES, MAX_VALUE_BYTES, MAX_VARIABLES_PER_PROFILE,
    SecretValue,
};

pub(crate) const MAX_DOTENV_INPUT_BYTES: usize = 2 * 1024 * 1024;
const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

/// One fully parsed data-only dotenv document.
///
/// The type intentionally implements neither `Debug` nor `Clone` because it
/// owns secret values.
pub(crate) struct DotenvDocument {
    variables: BTreeMap<EnvironmentName, SecretValue>,
}

impl DotenvDocument {
    pub(crate) fn variables(&self) -> &BTreeMap<EnvironmentName, SecretValue> {
        &self.variables
    }

    pub(crate) fn into_variables(self) -> BTreeMap<EnvironmentName, SecretValue> {
        self.variables
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }
}

/// Reads at most 2 MiB and parses Gschrank's strict, non-evaluating dotenv
/// dialect. The raw input buffer is zeroized when this function returns.
pub(crate) fn read_dotenv(reader: impl Read) -> Result<DotenvDocument, DotenvError> {
    let limit = u64::try_from(MAX_DOTENV_INPUT_BYTES)
        .expect("dotenv input limit fits u64")
        .saturating_add(1);
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(MAX_DOTENV_INPUT_BYTES.saturating_add(1))
        .map_err(|_| DotenvError::IoFailure)?;
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| DotenvError::IoFailure)?;
    if bytes.len() > MAX_DOTENV_INPUT_BYTES {
        return Err(DotenvError::InputLimitExceeded);
    }
    parse_dotenv(&bytes)
}

fn parse_dotenv(bytes: &[u8]) -> Result<DotenvDocument, DotenvError> {
    std::str::from_utf8(bytes).map_err(|_| DotenvError::InvalidUtf8)?;
    Parser::new(bytes).parse()
}

struct Parser<'source> {
    bytes: &'source [u8],
    cursor: usize,
    line: usize,
    variables: BTreeMap<EnvironmentName, SecretValue>,
    decoded_bytes: usize,
}

impl<'source> Parser<'source> {
    fn new(bytes: &'source [u8]) -> Self {
        Self {
            bytes,
            cursor: usize::from(bytes.starts_with(UTF8_BOM)) * UTF8_BOM.len(),
            line: 1,
            variables: BTreeMap::new(),
            decoded_bytes: 0,
        }
    }

    fn parse(mut self) -> Result<DotenvDocument, DotenvError> {
        while self.cursor < self.bytes.len() {
            self.skip_horizontal();
            match self.current() {
                None => break,
                Some(b'\n' | b'\r') => {
                    self.consume_newline()?;
                    continue;
                }
                Some(b'#') => {
                    self.skip_comment()?;
                    continue;
                }
                Some(_) => {}
            }
            self.parse_assignment()?;
        }
        Ok(DotenvDocument {
            variables: self.variables,
        })
    }

    fn parse_assignment(&mut self) -> Result<(), DotenvError> {
        let assignment_line = self.line;
        if self.bytes[self.cursor..].starts_with(b"export")
            && self
                .bytes
                .get(self.cursor + b"export".len())
                .is_some_and(|byte| is_horizontal(*byte))
        {
            self.cursor += b"export".len();
            self.skip_horizontal();
        }

        let name_start = self.cursor;
        while self
            .current()
            .is_some_and(|byte| !matches!(byte, b'=' | b'\n' | b'\r') && !is_horizontal(byte))
        {
            self.cursor += 1;
        }
        let name_bytes = &self.bytes[name_start..self.cursor];
        if name_bytes.is_empty() {
            return Err(DotenvError::InvalidName {
                line: assignment_line,
                kind: DomainError::InvalidEnvironmentName,
            });
        }
        if self.current() != Some(b'=') {
            return Err(DotenvError::InvalidSyntax {
                line: assignment_line,
            });
        }
        let name_text = std::str::from_utf8(name_bytes).map_err(|_| DotenvError::InvalidUtf8)?;
        let name = EnvironmentName::new(name_text).map_err(|kind| DotenvError::InvalidName {
            line: assignment_line,
            kind,
        })?;
        if self.variables.contains_key(&name) {
            return Err(DotenvError::DuplicateName {
                line: assignment_line,
                name,
            });
        }
        if self.variables.len() == MAX_VARIABLES_PER_PROFILE {
            return Err(DotenvError::VariableLimitExceeded);
        }
        self.cursor += 1;

        let had_leading_space = self.current().is_some_and(is_horizontal);
        self.skip_horizontal();
        let value = match self.current() {
            Some(b'\'') => self.parse_quoted(b'\'', &name, assignment_line)?,
            Some(b'"') => self.parse_quoted(b'"', &name, assignment_line)?,
            Some(b'#') if had_leading_space => {
                self.skip_comment()?;
                Zeroizing::new(Vec::new())
            }
            Some(b'\n' | b'\r') => {
                self.consume_newline()?;
                Zeroizing::new(Vec::new())
            }
            None => Zeroizing::new(Vec::new()),
            Some(_) => self.parse_unquoted()?,
        };
        let value =
            SecretValue::from_zeroizing(value).map_err(|kind| DotenvError::InvalidValue {
                line: assignment_line,
                name: name.clone(),
                kind,
            })?;
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.expose().len()))
            .ok_or(DotenvError::ProfileSizeLimitExceeded)?;
        if self.decoded_bytes > MAX_PROFILE_BYTES {
            return Err(DotenvError::ProfileSizeLimitExceeded);
        }
        self.variables.insert(name, value);
        Ok(())
    }

    fn parse_unquoted(&mut self) -> Result<Zeroizing<Vec<u8>>, DotenvError> {
        let start = self.cursor;
        let mut end = start;
        let mut comment = false;
        while let Some(byte) = self.current() {
            match byte {
                b'\n' | b'\r' => break,
                b'#' if self.cursor > start
                    && self
                        .bytes
                        .get(self.cursor - 1)
                        .is_some_and(|byte| is_horizontal(*byte)) =>
                {
                    comment = true;
                    break;
                }
                _ => {
                    self.cursor += 1;
                    end = self.cursor;
                }
            }
        }
        while end > start && is_horizontal(self.bytes[end - 1]) {
            end -= 1;
        }
        let value = Zeroizing::new(self.bytes[start..end].to_vec());
        if comment {
            self.skip_comment()?;
        } else if matches!(self.current(), Some(b'\n' | b'\r')) {
            self.consume_newline()?;
        }
        Ok(value)
    }

    fn parse_quoted(
        &mut self,
        quote: u8,
        name: &EnvironmentName,
        assignment_line: usize,
    ) -> Result<Zeroizing<Vec<u8>>, DotenvError> {
        self.cursor += 1;
        let mut value = Zeroizing::new(Vec::new());
        value
            .try_reserve(MAX_VALUE_BYTES.min(256))
            .map_err(|_| DotenvError::IoFailure)?;
        loop {
            let Some(byte) = self.current() else {
                return Err(DotenvError::UnterminatedQuote {
                    line: assignment_line,
                    name: name.clone(),
                });
            };
            if byte == quote {
                self.cursor += 1;
                self.consume_quoted_tail(assignment_line)?;
                return Ok(value);
            }
            if matches!(byte, b'\n' | b'\r') {
                self.consume_newline()?;
                push_value_byte(&mut value, b'\n')?;
                continue;
            }
            if quote == b'"' && byte == b'\\' {
                self.cursor += 1;
                let escaped = match self.current() {
                    Some(b'\\') => b'\\',
                    Some(b'"') => b'"',
                    Some(b'n') => b'\n',
                    Some(b'r') => b'\r',
                    Some(b't') => b'\t',
                    _ => {
                        return Err(DotenvError::UnsupportedEscape {
                            line: self.line,
                            name: name.clone(),
                        });
                    }
                };
                self.cursor += 1;
                push_value_byte(&mut value, escaped)?;
                continue;
            }
            self.cursor += 1;
            push_value_byte(&mut value, byte)?;
        }
    }

    fn consume_quoted_tail(&mut self, assignment_line: usize) -> Result<(), DotenvError> {
        self.skip_horizontal();
        match self.current() {
            None => Ok(()),
            Some(b'#') => self.skip_comment(),
            Some(b'\n' | b'\r') => self.consume_newline(),
            Some(_) => Err(DotenvError::InvalidSyntax {
                line: assignment_line,
            }),
        }
    }

    fn skip_comment(&mut self) -> Result<(), DotenvError> {
        while let Some(byte) = self.current() {
            if matches!(byte, b'\n' | b'\r') {
                return self.consume_newline();
            }
            self.cursor += 1;
        }
        Ok(())
    }

    fn consume_newline(&mut self) -> Result<(), DotenvError> {
        match self.current() {
            Some(b'\n') => self.cursor += 1,
            Some(b'\r') if self.bytes.get(self.cursor + 1) == Some(&b'\n') => self.cursor += 2,
            Some(b'\r') => return Err(DotenvError::BareCarriageReturn { line: self.line }),
            _ => return Err(DotenvError::InvalidSyntax { line: self.line }),
        }
        self.line = self
            .line
            .checked_add(1)
            .ok_or(DotenvError::InputLimitExceeded)?;
        Ok(())
    }

    fn skip_horizontal(&mut self) {
        while self.current().is_some_and(is_horizontal) {
            self.cursor += 1;
        }
    }

    fn current(&self) -> Option<u8> {
        self.bytes.get(self.cursor).copied()
    }
}

fn push_value_byte(value: &mut Zeroizing<Vec<u8>>, byte: u8) -> Result<(), DotenvError> {
    if value.len() == MAX_VALUE_BYTES {
        return Err(DotenvError::ValueLimitExceeded);
    }
    value.push(byte);
    Ok(())
}

const fn is_horizontal(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// A safe dotenv failure containing no source excerpt or value metadata.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DotenvError {
    IoFailure,
    InputLimitExceeded,
    InvalidUtf8,
    BareCarriageReturn {
        line: usize,
    },
    InvalidSyntax {
        line: usize,
    },
    InvalidName {
        line: usize,
        kind: DomainError,
    },
    DuplicateName {
        line: usize,
        name: EnvironmentName,
    },
    UnterminatedQuote {
        line: usize,
        name: EnvironmentName,
    },
    UnsupportedEscape {
        line: usize,
        name: EnvironmentName,
    },
    InvalidValue {
        line: usize,
        name: EnvironmentName,
        kind: DomainError,
    },
    VariableLimitExceeded,
    ValueLimitExceeded,
    ProfileSizeLimitExceeded,
}

impl DotenvError {
    pub(crate) const fn exit_code(&self) -> u8 {
        match self {
            Self::IoFailure => 1,
            Self::InputLimitExceeded
            | Self::InvalidUtf8
            | Self::BareCarriageReturn { .. }
            | Self::InvalidSyntax { .. }
            | Self::InvalidName { .. }
            | Self::DuplicateName { .. }
            | Self::UnterminatedQuote { .. }
            | Self::UnsupportedEscape { .. }
            | Self::InvalidValue { .. }
            | Self::VariableLimitExceeded
            | Self::ValueLimitExceeded
            | Self::ProfileSizeLimitExceeded => 2,
        }
    }
}

impl fmt::Display for DotenvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoFailure => formatter.write_str("dotenv input could not be read"),
            Self::InputLimitExceeded => formatter.write_str("dotenv input exceeds the 2 MiB limit"),
            Self::InvalidUtf8 => formatter.write_str("dotenv input must be valid UTF-8"),
            Self::BareCarriageReturn { line } => {
                write!(formatter, "bare carriage return on dotenv line {line}")
            }
            Self::InvalidSyntax { line } => {
                write!(formatter, "unsupported dotenv syntax on line {line}")
            }
            Self::InvalidName { line, kind } => {
                write!(formatter, "{kind} on dotenv line {line}")
            }
            Self::DuplicateName { line, name } => write!(
                formatter,
                "duplicate variable '{}' on dotenv line {line}",
                name.as_str()
            ),
            Self::UnterminatedQuote { line, name } => write!(
                formatter,
                "unterminated quoted value for '{}' starting on dotenv line {line}",
                name.as_str()
            ),
            Self::UnsupportedEscape { line, name } => write!(
                formatter,
                "unsupported escape in '{}' on dotenv line {line}",
                name.as_str()
            ),
            Self::InvalidValue { line, name, kind } => write!(
                formatter,
                "invalid value for '{}' on dotenv line {line}: {kind}",
                name.as_str()
            ),
            Self::VariableLimitExceeded => {
                formatter.write_str("dotenv input exceeds the variable limit")
            }
            Self::ValueLimitExceeded => formatter.write_str("a dotenv value exceeds its limit"),
            Self::ProfileSizeLimitExceeded => {
                formatter.write_str("dotenv values exceed the profile size limit")
            }
        }
    }
}

impl Error for DotenvError {}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn parsed(input: &[u8]) -> DotenvDocument {
        read_dotenv(Cursor::new(input)).unwrap()
    }

    fn rejected(input: impl AsRef<[u8]>) -> DotenvError {
        match read_dotenv(Cursor::new(input.as_ref())) {
            Ok(_) => panic!("expected dotenv input to be rejected"),
            Err(error) => error,
        }
    }

    fn exposed(document: &DotenvDocument, name: &str) -> Vec<u8> {
        document
            .variables()
            .get(&EnvironmentName::new(name).unwrap())
            .unwrap()
            .expose()
            .to_vec()
    }

    #[test]
    fn parses_the_complete_data_only_dialect_without_expansion() {
        let document = parsed(
            concat!(
                "\u{feff}  # comment\r\n",
                "export EMPTY=\r\n",
                "PLAIN=  literal $HOME $(cmd) `cmd` # comment\r\n",
                "HASH=literal#hash\n",
                "SINGLE='one\r\ntwo\\n$HOME' # tail\n",
                "DOUBLE=\"one\\ntwo\\r\\t\\\\\\\"$HOME\r\nthree\"\n",
            )
            .as_bytes(),
        );

        assert_eq!(exposed(&document, "EMPTY"), b"");
        assert_eq!(exposed(&document, "PLAIN"), b"literal $HOME $(cmd) `cmd`");
        assert_eq!(exposed(&document, "HASH"), b"literal#hash");
        assert_eq!(exposed(&document, "SINGLE"), b"one\ntwo\\n$HOME");
        assert_eq!(
            exposed(&document, "DOUBLE"),
            b"one\ntwo\r\t\\\"$HOME\nthree"
        );
    }

    #[test]
    fn accepts_empty_comments_only_and_empty_quoted_values() {
        assert!(parsed(b"\n\t# comment\r\n").is_empty());
        let document = parsed(b"A=''\nB=\"\"\nC=   # comment\n");
        for name in ["A", "B", "C"] {
            assert_eq!(exposed(&document, name), b"");
        }
    }

    #[test]
    fn rejects_duplicates_names_escapes_quotes_and_trailing_syntax_safely() {
        let cases = [
            (
                b"A=one\nA=two\n".as_slice(),
                "duplicate variable 'A' on dotenv line 2",
            ),
            (
                b"BAD-NAME=value\n",
                "invalid environment-variable name on dotenv line 1",
            ),
            (
                b"GSCHRANK_PRIVATE=value\n",
                "reserved environment-variable name on dotenv line 1",
            ),
            (
                b"A=\"bad\\q\"\n",
                "unsupported escape in 'A' on dotenv line 1",
            ),
            (
                b"A='missing\n",
                "unterminated quoted value for 'A' starting on dotenv line 1",
            ),
            (b"A='ok' trailing\n", "unsupported dotenv syntax on line 1"),
        ];
        for (input, expected) in cases {
            let error = rejected(input);
            assert_eq!(error.to_string(), expected);
        }

        let error = rejected(b"A='ok' CANARY-secret-source-excerpt\n");
        assert!(!error.to_string().contains("CANARY"));
    }

    #[test]
    fn rejects_bare_carriage_returns_invalid_utf8_nul_and_oversized_input() {
        assert!(matches!(
            read_dotenv(Cursor::new(b"A=one\rB=two")),
            Err(DotenvError::BareCarriageReturn { line: 1 })
        ));
        assert_eq!(rejected([b'A', b'=', 0xff]), DotenvError::InvalidUtf8);
        let nul = rejected([b'A', b'=', 0]);
        assert!(matches!(nul, DotenvError::InvalidValue { .. }));
        assert!(!nul.to_string().contains('\0'));

        let oversized = vec![b' '; MAX_DOTENV_INPUT_BYTES + 1];
        assert_eq!(rejected(oversized), DotenvError::InputLimitExceeded);
    }
}
