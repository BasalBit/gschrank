use std::{error::Error, fmt};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::{
    MAX_ENVELOPE_SIZE, PayloadError, Vault,
    codec::{decode_payload, encode_payload},
};

const MAGIC: &[u8; 8] = b"GSCHRANK";
const ENVELOPE_VERSION: u16 = 1;
const HEADER_LENGTH: usize = 80;
const CIPHER_SUITE: u16 = 1;
const TAG_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const AAD_DOMAIN: &[u8] = b"gschrank:vault-envelope:v1\0";

/// A public, opaque 128-bit vault identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VaultId([u8; 16]);

impl VaultId {
    /// Generates an identifier from the operating-system random source.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::RandomnessUnavailable`] if the operating system
    /// cannot provide secure random bytes.
    pub fn generate() -> Result<Self, EnvelopeError> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(|_| EnvelopeError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Constructs an identifier from exact wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the exact wire bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns lowercase hexadecimal for safe diagnostics.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

/// A public, opaque 128-bit secure-store lookup identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyId([u8; 16]);

impl KeyId {
    /// Generates an identifier from the operating-system random source.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::RandomnessUnavailable`] if the operating system
    /// cannot provide secure random bytes.
    pub fn generate() -> Result<Self, EnvelopeError> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(|_| EnvelopeError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Constructs an identifier from exact wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the exact wire bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns lowercase hexadecimal for the exact Keychain account name.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

/// A zeroizing 256-bit vault master key.
///
/// This type intentionally implements neither `Debug` nor `Display` nor
/// `Clone`.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// Generates a key from the operating-system random source.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::RandomnessUnavailable`] if the operating system
    /// cannot provide secure random bytes.
    pub fn generate() -> Result<Self, EnvelopeError> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *bytes).map_err(|_| EnvelopeError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    /// Takes ownership of exactly 32 key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Safe public metadata parsed before key lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeMetadata {
    pub vault_id: VaultId,
    pub key_id: KeyId,
    pub ciphertext_length: u64,
}

/// A completely authenticated and validated logical vault.
pub struct OpenedVault {
    pub vault_id: VaultId,
    pub key_id: KeyId,
    pub vault: Vault,
}

/// Encrypts a complete logical vault into a v1 authenticated envelope.
///
/// # Errors
///
/// Returns a safe [`EnvelopeError`] category if payload encoding, random nonce
/// generation, size validation, or authenticated encryption fails.
pub fn seal_vault(
    vault: &Vault,
    vault_id: VaultId,
    key_id: KeyId,
    key: &MasterKey,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    let plaintext = encode_payload(vault)?;
    let ciphertext_length = plaintext
        .len()
        .checked_add(TAG_LENGTH)
        .ok_or(EnvelopeError::TooLarge)?;
    let envelope_length = HEADER_LENGTH
        .checked_add(ciphertext_length)
        .ok_or(EnvelopeError::TooLarge)?;
    if envelope_length > MAX_ENVELOPE_SIZE {
        return Err(EnvelopeError::TooLarge);
    }

    let mut nonce = [0; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|_| EnvelopeError::RandomnessUnavailable)?;
    let header = encode_header(vault_id, key_id, ciphertext_length, nonce)?;
    let aad = associated_data(&header);
    let cipher_key =
        <&Key>::try_from(key.expose().as_slice()).map_err(|_| EnvelopeError::EncryptionFailed)?;
    let cipher_nonce =
        <&XNonce>::try_from(nonce.as_slice()).map_err(|_| EnvelopeError::EncryptionFailed)?;
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let ciphertext = cipher
        .encrypt(
            cipher_nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::EncryptionFailed)?;

    debug_assert_eq!(ciphertext.len(), ciphertext_length);
    let mut envelope = Zeroizing::new(Vec::with_capacity(envelope_length));
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

/// Parses and validates only public envelope metadata for exact key lookup.
///
/// # Errors
///
/// Returns a safe [`EnvelopeError`] category for malformed, unsupported,
/// truncated, trailing, or oversized input.
pub fn inspect_envelope(envelope: &[u8]) -> Result<EnvelopeMetadata, EnvelopeError> {
    parse_header(envelope).map(|parsed| parsed.metadata)
}

/// Authenticates, decrypts, and completely validates a v1 envelope.
///
/// # Errors
///
/// Returns a safe [`EnvelopeError`] category when the public envelope is
/// malformed, authentication fails, or the authenticated payload is invalid.
pub fn open_envelope(envelope: &[u8], key: &MasterKey) -> Result<OpenedVault, EnvelopeError> {
    let parsed = parse_header(envelope)?;
    let header = <&[u8; HEADER_LENGTH]>::try_from(
        envelope
            .get(..HEADER_LENGTH)
            .ok_or(EnvelopeError::Truncated)?,
    )
    .map_err(|_| EnvelopeError::InvalidHeader)?;
    let aad = associated_data(header);
    let cipher_key = <&Key>::try_from(key.expose().as_slice())
        .map_err(|_| EnvelopeError::AuthenticationFailed)?;
    let cipher_nonce =
        <&XNonce>::try_from(parsed.nonce.as_slice()).map_err(|_| EnvelopeError::InvalidHeader)?;
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let plaintext = cipher
        .decrypt(
            cipher_nonce,
            Payload {
                msg: &envelope[HEADER_LENGTH..],
                aad: &aad,
            },
        )
        .map_err(|_| EnvelopeError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    let vault = decode_payload(&plaintext)?;

    Ok(OpenedVault {
        vault_id: parsed.metadata.vault_id,
        key_id: parsed.metadata.key_id,
        vault,
    })
}

struct ParsedHeader {
    metadata: EnvelopeMetadata,
    nonce: [u8; NONCE_LENGTH],
}

fn parse_header(envelope: &[u8]) -> Result<ParsedHeader, EnvelopeError> {
    if envelope.len() > MAX_ENVELOPE_SIZE {
        return Err(EnvelopeError::TooLarge);
    }
    let header = envelope
        .get(..HEADER_LENGTH)
        .ok_or(EnvelopeError::Truncated)?;
    if &header[0..8] != MAGIC {
        return Err(EnvelopeError::InvalidMagic);
    }
    if read_u16(header, 8) != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    if usize::from(read_u16(header, 10)) != HEADER_LENGTH {
        return Err(EnvelopeError::InvalidHeader);
    }
    if read_u16(header, 12) != CIPHER_SUITE {
        return Err(EnvelopeError::UnsupportedCipherSuite);
    }
    if read_u16(header, 14) != 0 {
        return Err(EnvelopeError::InvalidHeader);
    }

    let vault_id = VaultId::from_bytes(header[16..32].try_into().expect("fixed-width slice"));
    let key_id = KeyId::from_bytes(header[32..48].try_into().expect("fixed-width slice"));
    let ciphertext_length = read_u64(header, 48);
    let ciphertext_length_usize =
        usize::try_from(ciphertext_length).map_err(|_| EnvelopeError::TooLarge)?;
    if ciphertext_length_usize < TAG_LENGTH {
        return Err(EnvelopeError::InvalidHeader);
    }
    let expected_length = HEADER_LENGTH
        .checked_add(ciphertext_length_usize)
        .ok_or(EnvelopeError::TooLarge)?;
    if expected_length > MAX_ENVELOPE_SIZE {
        return Err(EnvelopeError::TooLarge);
    }
    match envelope.len().cmp(&expected_length) {
        std::cmp::Ordering::Less => return Err(EnvelopeError::Truncated),
        std::cmp::Ordering::Greater => return Err(EnvelopeError::TrailingData),
        std::cmp::Ordering::Equal => {}
    }

    let nonce = header[56..80].try_into().expect("fixed-width slice");
    Ok(ParsedHeader {
        metadata: EnvelopeMetadata {
            vault_id,
            key_id,
            ciphertext_length,
        },
        nonce,
    })
}

fn encode_header(
    vault_id: VaultId,
    key_id: KeyId,
    ciphertext_length: usize,
    nonce: [u8; NONCE_LENGTH],
) -> Result<[u8; HEADER_LENGTH], EnvelopeError> {
    let ciphertext_length =
        u64::try_from(ciphertext_length).map_err(|_| EnvelopeError::TooLarge)?;
    let mut header = [0; HEADER_LENGTH];
    header[0..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    header[10..12].copy_from_slice(&80u16.to_be_bytes());
    header[12..14].copy_from_slice(&CIPHER_SUITE.to_be_bytes());
    header[14..16].copy_from_slice(&0u16.to_be_bytes());
    header[16..32].copy_from_slice(vault_id.as_bytes());
    header[32..48].copy_from_slice(key_id.as_bytes());
    header[48..56].copy_from_slice(&ciphertext_length.to_be_bytes());
    header[56..80].copy_from_slice(&nonce);
    Ok(header)
}

fn associated_data(header: &[u8; HEADER_LENGTH]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + HEADER_LENGTH);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(header);
    aad
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed-width slice"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed-width slice"),
    )
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Safe, secret-free envelope failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EnvelopeError {
    RandomnessUnavailable,
    TooLarge,
    Truncated,
    TrailingData,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedCipherSuite,
    InvalidHeader,
    EncryptionFailed,
    AuthenticationFailed,
    InvalidPayload(PayloadError),
}

impl From<PayloadError> for EnvelopeError {
    fn from(error: PayloadError) -> Self {
        Self::InvalidPayload(error)
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomnessUnavailable => "operating-system randomness unavailable",
            Self::TooLarge => "vault envelope limit exceeded",
            Self::Truncated => "truncated vault envelope",
            Self::TrailingData => "trailing vault envelope data",
            Self::InvalidMagic => "invalid vault envelope magic",
            Self::UnsupportedVersion => "unsupported vault envelope version",
            Self::UnsupportedCipherSuite => "unsupported vault cipher suite",
            Self::InvalidHeader => "invalid vault envelope header",
            Self::EncryptionFailed => "vault encryption failed",
            Self::AuthenticationFailed => "vault authentication failed",
            Self::InvalidPayload(_) => "invalid authenticated vault payload",
        })
    }
}

impl Error for EnvelopeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EnvironmentName, ProfileName, SecretValue};

    fn fixture() -> (Vault, VaultId, KeyId, MasterKey) {
        let mut vault = Vault::empty();
        let profile = ProfileName::new("dev").unwrap();
        vault.create_profile(profile.clone()).unwrap();
        vault
            .set(
                &profile,
                EnvironmentName::new("API_KEY").unwrap(),
                SecretValue::from_string("canary-secret".to_owned()).unwrap(),
            )
            .unwrap();
        (
            vault,
            VaultId::from_bytes([0x11; 16]),
            KeyId::from_bytes([0x22; 16]),
            MasterKey::from_bytes([0x33; 32]),
        )
    }

    fn open_error(envelope: &[u8], key: &MasterKey) -> EnvelopeError {
        match open_envelope(envelope, key) {
            Ok(_) => panic!("expected envelope opening to fail"),
            Err(error) => error,
        }
    }

    #[test]
    fn envelope_round_trips_and_exposes_only_routing_metadata() {
        let (vault, vault_id, key_id, key) = fixture();
        let envelope = seal_vault(&vault, vault_id, key_id, &key).unwrap();
        assert!(
            !envelope
                .windows(b"canary-secret".len())
                .any(|window| window == b"canary-secret")
        );

        let metadata = inspect_envelope(&envelope).unwrap();
        assert_eq!(metadata.vault_id, vault_id);
        assert_eq!(metadata.key_id, key_id);
        assert_eq!(
            usize::try_from(metadata.ciphertext_length).unwrap(),
            envelope.len() - HEADER_LENGTH
        );
        assert_eq!(&envelope[0..8], MAGIC);
        assert_eq!(&envelope[8..10], &1u16.to_be_bytes());
        assert_eq!(&envelope[10..12], &80u16.to_be_bytes());
        assert_eq!(&envelope[12..14], &1u16.to_be_bytes());
        assert_eq!(&envelope[14..16], &0u16.to_be_bytes());
        assert_eq!(&envelope[16..32], vault_id.as_bytes());
        assert_eq!(&envelope[32..48], key_id.as_bytes());

        let opened = open_envelope(&envelope, &key).unwrap();
        let profile = ProfileName::new("dev").unwrap();
        let variable = EnvironmentName::new("API_KEY").unwrap();
        assert_eq!(
            opened.vault.secret(&profile, &variable),
            Some(b"canary-secret".as_slice())
        );
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let (vault, vault_id, key_id, key) = fixture();
        let first = seal_vault(&vault, vault_id, key_id, &key).unwrap();
        let second = seal_vault(&vault, vault_id, key_id, &key).unwrap();
        assert_ne!(&first[56..80], &second[56..80]);
        assert_ne!(&*first, &*second);
    }

    #[test]
    fn wrong_key_and_tampering_share_authentication_failure() {
        let (vault, vault_id, key_id, key) = fixture();
        let envelope = seal_vault(&vault, vault_id, key_id, &key).unwrap();
        let wrong_key = MasterKey::from_bytes([0x44; 32]);
        assert_eq!(
            open_error(&envelope, &wrong_key),
            EnvelopeError::AuthenticationFailed
        );

        let mut ciphertext_tamper = envelope.to_vec();
        ciphertext_tamper[HEADER_LENGTH] ^= 1;
        assert_eq!(
            open_error(&ciphertext_tamper, &key),
            EnvelopeError::AuthenticationFailed
        );

        let mut header_tamper = envelope.to_vec();
        header_tamper[16] ^= 1;
        assert_eq!(
            open_error(&header_tamper, &key),
            EnvelopeError::AuthenticationFailed
        );

        let mut nonce_tamper = envelope.to_vec();
        nonce_tamper[56] ^= 1;
        assert_eq!(
            open_error(&nonce_tamper, &key),
            EnvelopeError::AuthenticationFailed
        );
    }

    #[test]
    fn rejects_truncation_trailing_data_and_unknown_suite() {
        let (vault, vault_id, key_id, key) = fixture();
        let envelope = seal_vault(&vault, vault_id, key_id, &key).unwrap();
        assert_eq!(
            inspect_envelope(&envelope[..envelope.len() - 1]).unwrap_err(),
            EnvelopeError::Truncated
        );

        let mut trailing = envelope.to_vec();
        trailing.push(0);
        assert_eq!(
            inspect_envelope(&trailing).unwrap_err(),
            EnvelopeError::TrailingData
        );

        let mut unknown_suite = envelope.to_vec();
        unknown_suite[13] = 2;
        assert_eq!(
            inspect_envelope(&unknown_suite).unwrap_err(),
            EnvelopeError::UnsupportedCipherSuite
        );
    }

    #[test]
    fn every_prefix_of_an_envelope_is_rejected_as_truncated() {
        let (vault, vault_id, key_id, key) = fixture();
        let envelope = seal_vault(&vault, vault_id, key_id, &key).unwrap();
        for length in 0..envelope.len() {
            assert_eq!(
                inspect_envelope(&envelope[..length]).unwrap_err(),
                EnvelopeError::Truncated,
                "prefix length {length}"
            );
        }
    }

    #[test]
    fn identifiers_use_fixed_lowercase_hex() {
        assert_eq!(
            KeyId::from_bytes([0xab; 16]).to_hex(),
            "abababababababababababababababab"
        );
    }

    #[test]
    fn public_errors_never_include_secret_bytes() {
        let error = open_error(b"canary-secret", &MasterKey::from_bytes([0; 32])).to_string();
        assert!(!error.contains("canary-secret"));
    }
}
