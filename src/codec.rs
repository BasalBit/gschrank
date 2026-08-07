use std::{collections::BTreeMap, error::Error, fmt};

use zeroize::Zeroizing;

use crate::{
    DomainError, EnvironmentName, MAX_ENVELOPE_SIZE, MAX_PROFILE_BYTES, MAX_PROFILE_NAME_BYTES,
    MAX_PROFILES, MAX_VALUE_BYTES, MAX_VARIABLE_NAME_BYTES, MAX_VARIABLES_PER_PROFILE, ProfileName,
    SecretValue, Vault,
};

const SCHEMA_VERSION: u16 = 1;
const HEADER_AND_TAG_BYTES: usize = 80 + 16;
const MAX_PAYLOAD_SIZE: usize = MAX_ENVELOPE_SIZE - HEADER_AND_TAG_BYTES;

/// Encodes a logical vault using Gschrank's deterministic v1 payload format.
///
/// # Errors
///
/// Returns [`PayloadError::LimitExceeded`] if the encoded vault cannot fit in
/// a v1 envelope.
pub(crate) fn encode_payload(vault: &Vault) -> Result<Zeroizing<Vec<u8>>, PayloadError> {
    let encoded_length = encoded_length(vault)?;
    let mut output = Zeroizing::new(Vec::with_capacity(encoded_length));
    put_u16(&mut output, SCHEMA_VERSION);
    put_u16(&mut output, 0);
    put_u64(&mut output, vault.revision());
    put_u32(
        &mut output,
        u32::try_from(vault.profile_names().len()).map_err(|_| PayloadError::LimitExceeded)?,
    );

    for (profile, variables) in vault.profiles() {
        put_bytes_u16(&mut output, profile.as_str().as_bytes())?;
        put_u32(
            &mut output,
            u32::try_from(variables.len()).map_err(|_| PayloadError::LimitExceeded)?,
        );
        for (name, value) in variables {
            put_bytes_u16(&mut output, name.as_str().as_bytes())?;
            put_bytes_u32(&mut output, value.expose())?;
        }
    }

    debug_assert_eq!(output.len(), encoded_length);
    Ok(output)
}

fn encoded_length(vault: &Vault) -> Result<usize, PayloadError> {
    let mut length = 2 + 2 + 8 + 4;
    for (profile, variables) in vault.profiles() {
        length = add_length(length, 2 + profile.as_str().len() + 4)?;
        for (name, value) in variables {
            length = add_length(length, 2 + name.as_str().len() + 4)?;
            length = add_length(length, value.expose().len())?;
        }
    }
    Ok(length)
}

fn add_length(current: usize, additional: usize) -> Result<usize, PayloadError> {
    let length = current
        .checked_add(additional)
        .ok_or(PayloadError::LimitExceeded)?;
    if length > MAX_PAYLOAD_SIZE {
        Err(PayloadError::LimitExceeded)
    } else {
        Ok(length)
    }
}

/// Decodes and fully validates Gschrank's deterministic v1 payload format.
///
/// # Errors
///
/// Returns a safe [`PayloadError`] category for malformed, noncanonical,
/// unsupported, or resource-limit-violating input.
pub(crate) fn decode_payload(input: &[u8]) -> Result<Vault, PayloadError> {
    if input.len() > MAX_PAYLOAD_SIZE {
        return Err(PayloadError::LimitExceeded);
    }

    let mut decoder = Decoder::new(input);
    if decoder.u16()? != SCHEMA_VERSION {
        return Err(PayloadError::UnsupportedVersion);
    }
    if decoder.u16()? != 0 {
        return Err(PayloadError::InvalidFlags);
    }
    let revision = decoder.u64()?;
    let profile_count = decoder.u32_as_usize()?;
    if profile_count > MAX_PROFILES {
        return Err(PayloadError::LimitExceeded);
    }

    let mut profiles = BTreeMap::new();
    let mut previous_profile: Option<ProfileName> = None;
    for _ in 0..profile_count {
        let profile_name_length = usize::from(decoder.u16()?);
        if profile_name_length > MAX_PROFILE_NAME_BYTES {
            return Err(PayloadError::InvalidProfile);
        }
        let raw_name = decoder.take(profile_name_length)?;
        let name = std::str::from_utf8(raw_name)
            .map_err(|_| PayloadError::InvalidProfile)
            .and_then(|name| ProfileName::new(name).map_err(PayloadError::from_domain))?;
        if previous_profile
            .as_ref()
            .is_some_and(|previous| previous >= &name)
        {
            return Err(PayloadError::NonCanonicalOrder);
        }

        let variable_count = decoder.u32_as_usize()?;
        if variable_count > MAX_VARIABLES_PER_PROFILE {
            return Err(PayloadError::LimitExceeded);
        }
        let mut variables = BTreeMap::new();
        let mut previous_variable: Option<EnvironmentName> = None;
        let mut profile_bytes = 0usize;
        for _ in 0..variable_count {
            let variable_name_length = usize::from(decoder.u16()?);
            if variable_name_length > MAX_VARIABLE_NAME_BYTES {
                return Err(PayloadError::InvalidVariable);
            }
            let raw_variable = decoder.take(variable_name_length)?;
            let variable = std::str::from_utf8(raw_variable)
                .map_err(|_| PayloadError::InvalidVariable)
                .and_then(|name| EnvironmentName::new(name).map_err(PayloadError::from_domain))?;
            if previous_variable
                .as_ref()
                .is_some_and(|previous| previous >= &variable)
            {
                return Err(PayloadError::NonCanonicalOrder);
            }

            let value_length = decoder.u32_as_usize()?;
            if value_length > MAX_VALUE_BYTES {
                return Err(PayloadError::LimitExceeded);
            }
            let raw_value = decoder.take(value_length)?;
            profile_bytes = profile_bytes
                .checked_add(raw_variable.len())
                .and_then(|total| total.checked_add(raw_value.len()))
                .ok_or(PayloadError::LimitExceeded)?;
            if profile_bytes > MAX_PROFILE_BYTES {
                return Err(PayloadError::LimitExceeded);
            }
            if raw_value.contains(&0) || std::str::from_utf8(raw_value).is_err() {
                return Err(PayloadError::InvalidValue);
            }
            let value = SecretValue::new(raw_value.to_vec()).map_err(PayloadError::from_domain)?;
            previous_variable = Some(variable.clone());
            variables.insert(variable, value);
        }

        previous_profile = Some(name.clone());
        profiles.insert(name, variables);
    }

    if !decoder.is_finished() {
        return Err(PayloadError::TrailingData);
    }

    Vault::from_parts(revision, profiles).map_err(PayloadError::from_domain)
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes_u16(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PayloadError> {
    let length = u16::try_from(value.len()).map_err(|_| PayloadError::LimitExceeded)?;
    put_u16(output, length);
    output.extend_from_slice(value);
    Ok(())
}

fn put_bytes_u32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PayloadError> {
    let length = u32::try_from(value.len()).map_err(|_| PayloadError::LimitExceeded)?;
    put_u32(output, length);
    output.extend_from_slice(value);
    Ok(())
}

struct Decoder<'input> {
    input: &'input [u8],
    position: usize,
}

impl<'input> Decoder<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'input [u8], PayloadError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(PayloadError::Truncated)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(PayloadError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, PayloadError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().expect("fixed-width slice");
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, PayloadError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("fixed-width slice");
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, PayloadError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("fixed-width slice");
        Ok(u64::from_be_bytes(bytes))
    }

    fn u32_as_usize(&mut self) -> Result<usize, PayloadError> {
        usize::try_from(self.u32()?).map_err(|_| PayloadError::LimitExceeded)
    }

    const fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }
}

/// Safe, value-free payload failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PayloadError {
    UnsupportedVersion,
    InvalidFlags,
    Truncated,
    InvalidProfile,
    InvalidVariable,
    InvalidValue,
    NonCanonicalOrder,
    TrailingData,
    LimitExceeded,
}

impl PayloadError {
    fn from_domain(error: DomainError) -> Self {
        match error {
            DomainError::InvalidProfileName => Self::InvalidProfile,
            DomainError::InvalidEnvironmentName | DomainError::ReservedEnvironmentName => {
                Self::InvalidVariable
            }
            DomainError::InvalidValue
            | DomainError::ProfileAlreadyExists
            | DomainError::ProfileNotFound
            | DomainError::VariableNotFound
            | DomainError::RevisionExhausted => Self::InvalidValue,
            DomainError::ProfileLimitExceeded
            | DomainError::VariableLimitExceeded
            | DomainError::ValueLimitExceeded
            | DomainError::ProfileSizeLimitExceeded => Self::LimitExceeded,
        }
    }
}

impl fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "unsupported payload version",
            Self::InvalidFlags => "invalid payload flags",
            Self::Truncated => "truncated payload",
            Self::InvalidProfile => "invalid profile record",
            Self::InvalidVariable => "invalid variable record",
            Self::InvalidValue => "invalid value record",
            Self::NonCanonicalOrder => "payload records are not in canonical order",
            Self::TrailingData => "trailing payload data",
            Self::LimitExceeded => "payload resource limit exceeded",
        })
    }
}

impl Error for PayloadError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vault {
        let mut vault = Vault::empty();
        let dev = ProfileName::new("dev").unwrap();
        vault.create_profile(dev.clone()).unwrap();
        vault
            .set(
                &dev,
                EnvironmentName::new("API_KEY").unwrap(),
                SecretValue::from_string("canary-secret".to_owned()).unwrap(),
            )
            .unwrap();
        vault
    }

    fn decode_error(input: &[u8]) -> PayloadError {
        match decode_payload(input) {
            Ok(_) => panic!("expected payload decoding to fail"),
            Err(error) => error,
        }
    }

    fn one_variable_payload(variable: &[u8], value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        put_u16(&mut bytes, 1);
        put_u16(&mut bytes, 0);
        put_u64(&mut bytes, 0);
        put_u32(&mut bytes, 1);
        put_bytes_u16(&mut bytes, b"dev").unwrap();
        put_u32(&mut bytes, 1);
        put_bytes_u16(&mut bytes, variable).unwrap();
        put_bytes_u32(&mut bytes, value).unwrap();
        bytes
    }

    #[test]
    fn encoding_is_deterministic_and_round_trips() {
        let vault = fixture();
        let first = encode_payload(&vault).unwrap();
        let second = encode_payload(&vault).unwrap();
        assert!(
            first.as_slice() == second.as_slice(),
            "deterministic payload encoding mismatch"
        );

        let decoded = decode_payload(&first).unwrap();
        let dev = ProfileName::new("dev").unwrap();
        let key = EnvironmentName::new("API_KEY").unwrap();
        assert_eq!(decoded.revision(), 2);
        assert!(
            decoded.secret(&dev, &key) == Some(b"canary-secret".as_slice()),
            "decoded secret bytes mismatch"
        );
    }

    #[test]
    fn empty_vault_has_a_stable_wire_representation() {
        let bytes = encode_payload(&Vault::empty()).unwrap();
        assert_eq!(
            &*bytes,
            &[
                0, 1, // schema
                0, 0, // flags
                0, 0, 0, 0, 0, 0, 0, 0, // revision
                0, 0, 0, 0, // profiles
            ]
        );
    }

    #[test]
    fn rejects_truncation_and_trailing_data() {
        let bytes = encode_payload(&fixture()).unwrap();
        assert_eq!(
            decode_error(&bytes[..bytes.len() - 1]),
            PayloadError::Truncated
        );

        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert_eq!(decode_error(&trailing), PayloadError::TrailingData);
    }

    #[test]
    fn rejects_noncanonical_profile_order() {
        let mut bytes = Vec::new();
        put_u16(&mut bytes, 1);
        put_u16(&mut bytes, 0);
        put_u64(&mut bytes, 0);
        put_u32(&mut bytes, 2);
        put_bytes_u16(&mut bytes, b"z").unwrap();
        put_u32(&mut bytes, 0);
        put_bytes_u16(&mut bytes, b"a").unwrap();
        put_u32(&mut bytes, 0);

        assert_eq!(decode_error(&bytes), PayloadError::NonCanonicalOrder);
    }

    #[test]
    fn rejects_duplicate_variables_reserved_names_and_invalid_values() {
        let mut duplicate = Vec::new();
        put_u16(&mut duplicate, 1);
        put_u16(&mut duplicate, 0);
        put_u64(&mut duplicate, 0);
        put_u32(&mut duplicate, 1);
        put_bytes_u16(&mut duplicate, b"dev").unwrap();
        put_u32(&mut duplicate, 2);
        for _ in 0..2 {
            put_bytes_u16(&mut duplicate, b"A").unwrap();
            put_bytes_u32(&mut duplicate, b"").unwrap();
        }
        assert_eq!(decode_error(&duplicate), PayloadError::NonCanonicalOrder);
        assert_eq!(
            decode_error(&one_variable_payload(b"GSCHRANK_ACTIVE", b"value")),
            PayloadError::InvalidVariable
        );
        assert_eq!(
            decode_error(&one_variable_payload(b"A", b"nul\0value")),
            PayloadError::InvalidValue
        );
        assert_eq!(
            decode_error(&one_variable_payload(b"A", &[0xff])),
            PayloadError::InvalidValue
        );
    }

    #[test]
    fn rejects_oversized_declared_value_before_reading_it() {
        let mut bytes = one_variable_payload(b"A", b"");
        let value_length_offset = bytes.len() - 4;
        bytes[value_length_offset..]
            .copy_from_slice(&u32::try_from(MAX_VALUE_BYTES + 1).unwrap().to_be_bytes());
        assert_eq!(decode_error(&bytes), PayloadError::LimitExceeded);
    }

    #[test]
    fn preserves_empty_unicode_and_shell_metacharacter_values() {
        let mut vault = Vault::empty();
        let dev = ProfileName::new("dev").unwrap();
        vault.create_profile(dev.clone()).unwrap();
        let cases = [
            ("EMPTY", ""),
            ("UNICODE", "välue 🗝️"),
            ("SHELL", "  $HOME $(false) `false` ' \" \\\n\t  "),
        ];
        for (name, value) in cases {
            vault
                .set(
                    &dev,
                    EnvironmentName::new(name).unwrap(),
                    SecretValue::from_string(value.to_owned()).unwrap(),
                )
                .unwrap();
        }

        let decoded = decode_payload(&encode_payload(&vault).unwrap()).unwrap();
        for (name, value) in cases {
            let name = EnvironmentName::new(name).unwrap();
            assert!(
                decoded.secret(&dev, &name) == Some(value.as_bytes()),
                "decoded hostile-value bytes mismatch"
            );
        }
    }

    #[test]
    fn errors_do_not_include_secret_bytes() {
        let error = decode_error(b"canary-secret").to_string();
        assert!(
            !error.contains("canary-secret"),
            "payload error exposed secret bytes"
        );
    }
}
