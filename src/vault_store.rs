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

/// Read access while the store retains its stable shared or exclusive lock.
pub(crate) trait VaultRead {
    fn read_live(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError>;
}

/// Initialization artifact operations while the exclusive lock is retained.
pub(crate) trait VaultTransaction: VaultRead {
    fn read_init_pending(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultStoreError>;
    fn create_init_pending(&mut self, envelope: &[u8]) -> Result<(), VaultStoreError>;
    fn discard_init_pending(&mut self) -> Result<(), VaultStoreError>;
    fn promote_init_pending(&mut self) -> Result<CommitOutcome, VaultStoreError>;
    fn replace_live(&mut self, envelope: &[u8]) -> Result<CommitOutcome, VaultStoreError>;
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
