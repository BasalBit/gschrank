#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use zeroize::Zeroizing;

/// The portable semantic result of a local-vault-store failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VaultStoreErrorKind {
    MissingState,
    UnsafePath,
    PermissionDenied,
    LockFailure,
    UnsupportedStorage,
    Conflict,
    IoFailure,
    OutcomeIndeterminate,
}

/// A safe local-store failure containing no secret bytes or user paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VaultStoreError {
    kind: VaultStoreErrorKind,
    native_code: Option<i32>,
}

impl VaultStoreError {
    pub(crate) const fn new(kind: VaultStoreErrorKind) -> Self {
        Self {
            kind,
            native_code: None,
        }
    }

    pub(crate) const fn with_native_code(kind: VaultStoreErrorKind, native_code: i32) -> Self {
        Self {
            kind,
            native_code: Some(native_code),
        }
    }

    pub(crate) const fn kind(self) -> VaultStoreErrorKind {
        self.kind
    }

    #[allow(dead_code)]
    pub(crate) const fn native_code(self) -> Option<i32> {
        self.native_code
    }
}

impl fmt::Display for VaultStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            VaultStoreErrorKind::MissingState => "vault store is not initialized",
            VaultStoreErrorKind::UnsafePath => "unsafe vault-store path",
            VaultStoreErrorKind::PermissionDenied => "vault-store permission denied",
            VaultStoreErrorKind::LockFailure => "vault-store lock failed",
            VaultStoreErrorKind::UnsupportedStorage => "unsupported vault storage",
            VaultStoreErrorKind::Conflict => "vault-store state conflict",
            VaultStoreErrorKind::IoFailure => "vault-store I/O failure",
            VaultStoreErrorKind::OutcomeIndeterminate => "vault-store outcome indeterminate",
        })
    }
}

impl Error for VaultStoreError {}

/// Whether an atomic promotion is known to have committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CommitOutcome {
    Committed,
    #[allow(dead_code)]
    NotCommitted,
    #[allow(dead_code)]
    Indeterminate,
}

/// An opaque, user-safe identifier for one durable internal recovery bundle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RecoveryBundleId([u8; 16]);

impl RecoveryBundleId {
    #[allow(dead_code)]
    pub(crate) fn generate() -> Result<Self, VaultStoreError> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::IoFailure))?;
        Ok(Self(bytes))
    }

    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub(crate) fn from_hex(encoded: &str) -> Option<Self> {
        if encoded.len() != 32
            || !encoded
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_hex_nibble(pair[0])?;
            let low = decode_hex_nibble(pair[1])?;
            bytes[index] = (high << 4) | low;
        }
        Some(Self(bytes))
    }

    #[allow(dead_code)]
    pub(crate) const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(32);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// The explicit lifecycle operation that caused a recovery bundle to exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryReason {
    Restore,
    Reset,
    Rebuild,
}

impl RecoveryReason {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Restore => "restore",
            Self::Reset => "reset",
            Self::Rebuild => "rebuild",
        }
    }
}

/// Safe, versioned metadata for one recovery bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryBundleMetadata {
    pub(crate) id: RecoveryBundleId,
    pub(crate) created_at_unix_seconds: u64,
    pub(crate) reason: RecoveryReason,
}

/// Exact encrypted artifacts read from one committed recovery bundle.
pub(crate) struct RecoveryBundle {
    pub(crate) metadata: RecoveryBundleMetadata,
    pub(crate) live: Option<Zeroizing<Vec<u8>>>,
    pub(crate) init_pending: Option<Zeroizing<Vec<u8>>>,
}

/// Borrowed encrypted artifacts to preserve as one recovery bundle.
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct RecoveryArtifacts<'artifacts> {
    pub(crate) live: Option<&'artifacts [u8]>,
    pub(crate) init_pending: Option<&'artifacts [u8]>,
}

/// Read access while the store retains its stable shared or exclusive lock.
pub(crate) trait VaultRead {
    fn read_live(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError>;
    fn read_init_pending(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError>;
    fn read_recovery_bundles(&mut self) -> Result<Vec<RecoveryBundle>, VaultStoreError>;
}

/// Initialization artifact operations while the exclusive lock is retained.
pub(crate) trait VaultTransaction: VaultRead {
    fn create_init_pending(&mut self, envelope: &[u8]) -> Result<(), VaultStoreError>;
    fn discard_init_pending(&mut self) -> Result<(), VaultStoreError>;
    fn promote_init_pending(&mut self) -> Result<CommitOutcome, VaultStoreError>;
    /// Remove the live and reserved initialization artifacts after an exact
    /// recovery copy has been committed. Recovery bundles are never touched.
    fn clear_root_artifacts(&mut self) -> Result<CommitOutcome, VaultStoreError>;
    fn install_live(&mut self, envelope: &[u8]) -> Result<CommitOutcome, VaultStoreError>;
    fn replace_live(&mut self, envelope: &[u8]) -> Result<CommitOutcome, VaultStoreError>;
    #[allow(dead_code)]
    fn preserve_recovery(
        &mut self,
        metadata: RecoveryBundleMetadata,
        artifacts: RecoveryArtifacts<'_>,
    ) -> Result<CommitOutcome, VaultStoreError>;
}

/// Transaction-level access to encrypted vault artifacts.
pub(crate) trait VaultStore: Send + Sync {
    fn initialization_transaction<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<VaultStoreError>,
        F: FnOnce(&mut dyn VaultTransaction) -> Result<T, E>;

    #[allow(dead_code)]
    fn shared_read<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<VaultStoreError>,
        F: FnOnce(&mut dyn VaultRead) -> Result<T, E>;

    fn exclusive_transaction<T, E, F>(&self, operation: F) -> Result<T, E>
    where
        E: From<VaultStoreError>,
        F: FnOnce(&mut dyn VaultTransaction) -> Result<T, E>;
}
