#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use crate::{KeyId, MasterKey};

/// Whether a secure-store operation may show native authentication UI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InteractionPolicy {
    AllowPrompt,
    FailFast,
}

/// The portable semantic result of a secure-store failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyProviderErrorKind {
    NotFound,
    AlreadyExists,
    UserCancelled,
    AuthenticationFailed,
    InteractionRequired,
    PermissionDenied,
    Unavailable,
    InvalidKeyMaterial,
    BackendFailure,
}

/// A safe secure-store failure containing no key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyProviderError {
    kind: KeyProviderErrorKind,
    native_code: Option<i32>,
}

impl KeyProviderError {
    pub(crate) const fn new(kind: KeyProviderErrorKind) -> Self {
        Self {
            kind,
            native_code: None,
        }
    }

    pub(crate) const fn with_native_code(kind: KeyProviderErrorKind, native_code: i32) -> Self {
        Self {
            kind,
            native_code: Some(native_code),
        }
    }

    pub(crate) const fn kind(self) -> KeyProviderErrorKind {
        self.kind
    }

    #[allow(dead_code)]
    pub(crate) const fn native_code(self) -> Option<i32> {
        self.native_code
    }

    pub(crate) const fn definitely_did_not_store(self) -> bool {
        matches!(
            self.kind,
            KeyProviderErrorKind::AlreadyExists
                | KeyProviderErrorKind::UserCancelled
                | KeyProviderErrorKind::AuthenticationFailed
                | KeyProviderErrorKind::InteractionRequired
                | KeyProviderErrorKind::PermissionDenied
                | KeyProviderErrorKind::Unavailable
                | KeyProviderErrorKind::InvalidKeyMaterial
        )
    }
}

impl fmt::Display for KeyProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            KeyProviderErrorKind::NotFound => "secure-store item not found",
            KeyProviderErrorKind::AlreadyExists => "secure-store item already exists",
            KeyProviderErrorKind::UserCancelled => "secure-store interaction cancelled",
            KeyProviderErrorKind::AuthenticationFailed => "secure-store authentication failed",
            KeyProviderErrorKind::InteractionRequired => "secure-store interaction required",
            KeyProviderErrorKind::PermissionDenied => "secure-store permission denied",
            KeyProviderErrorKind::Unavailable => "secure store unavailable",
            KeyProviderErrorKind::InvalidKeyMaterial => "invalid secure-store key material",
            KeyProviderErrorKind::BackendFailure => "secure-store backend failure",
        })
    }
}

impl Error for KeyProviderError {}

/// Exact create/load/delete access to platform secure key storage.
pub(crate) trait KeyProvider: Send + Sync {
    fn load(
        &self,
        key_id: &KeyId,
        interaction: InteractionPolicy,
    ) -> Result<MasterKey, KeyProviderError>;

    fn store_new(
        &self,
        key_id: &KeyId,
        key: &MasterKey,
        interaction: InteractionPolicy,
    ) -> Result<(), KeyProviderError>;

    fn delete(
        &self,
        key_id: &KeyId,
        interaction: InteractionPolicy,
    ) -> Result<(), KeyProviderError>;
}
