#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use crate::{
    KeyId, VaultId, inspect_envelope,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderErrorKind},
    open_envelope,
    vault_store::{
        RecoveryBundle, RecoveryBundleId, RecoveryReason, VaultStore, VaultStoreError,
        VaultStoreErrorKind,
    },
};

/// Safe authentication result for every encrypted artifact in one bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryAuthentication {
    Authenticated,
    KeyMissing,
    InvalidKeyMaterial,
    SecureStoreUnavailable,
    Unreadable,
}

impl RecoveryAuthentication {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::KeyMissing => "key missing",
            Self::InvalidKeyMaterial => "key invalid",
            Self::SecureStoreUnavailable => "key unavailable",
            Self::Unreadable => "unreadable",
        }
    }

    const fn exit_code(self) -> u8 {
        match self {
            Self::Authenticated => 0,
            Self::SecureStoreUnavailable => 11,
            Self::KeyMissing | Self::InvalidKeyMaterial | Self::Unreadable => 12,
        }
    }
}

/// Value- and name-free information for one internal recovery bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryInspection {
    pub(crate) id: RecoveryBundleId,
    pub(crate) created_at_unix_seconds: u64,
    pub(crate) reason: RecoveryReason,
    pub(crate) vault_id: Option<VaultId>,
    pub(crate) key_id: Option<KeyId>,
    pub(crate) authentication: RecoveryAuthentication,
}

/// Safe results of listing and validating all internal recovery bundles.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RecoveryList {
    pub(crate) bundles: Vec<RecoveryInspection>,
    pub(crate) purge_pending: Vec<RecoveryBundleId>,
}

impl RecoveryList {
    pub(crate) fn exit_code(&self) -> u8 {
        let bundle_exit = self
            .bundles
            .iter()
            .map(|bundle| bundle.authentication.exit_code())
            .max()
            .unwrap_or(0);
        if self.purge_pending.is_empty() {
            bundle_exit
        } else {
            bundle_exit.max(14)
        }
    }
}

/// Store-only lifecycle inventory used by status and doctor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryOverview {
    pub(crate) initialization_pending: bool,
    pub(crate) rebuild_pending: bool,
    pub(crate) bundle_count: usize,
    pub(crate) purge_pending_count: usize,
}

/// A safe recovery inventory failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryOperationError(VaultStoreError);

impl RecoveryOperationError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self.0.kind() {
            VaultStoreErrorKind::UnsafePath
            | VaultStoreErrorKind::PermissionDenied
            | VaultStoreErrorKind::UnsupportedStorage => 13,
            VaultStoreErrorKind::Conflict => 14,
            VaultStoreErrorKind::OutcomeIndeterminate => 15,
            VaultStoreErrorKind::MissingState
            | VaultStoreErrorKind::LockFailure
            | VaultStoreErrorKind::IoFailure => 1,
        }
    }

    pub(crate) const fn kind(self) -> VaultStoreErrorKind {
        self.0.kind()
    }
}

impl From<VaultStoreError> for RecoveryOperationError {
    fn from(error: VaultStoreError) -> Self {
        Self(error)
    }
}

impl fmt::Display for RecoveryOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.0.kind() {
            VaultStoreErrorKind::MissingState => "internal recovery storage is not initialized",
            VaultStoreErrorKind::UnsafePath => "internal recovery storage is unsafe",
            VaultStoreErrorKind::PermissionDenied => {
                "internal recovery storage permission was denied"
            }
            VaultStoreErrorKind::LockFailure => "internal recovery storage could not be locked",
            VaultStoreErrorKind::UnsupportedStorage => "internal recovery storage is unsupported",
            VaultStoreErrorKind::Conflict => "internal recovery storage is ambiguous",
            VaultStoreErrorKind::IoFailure => "internal recovery storage could not be read",
            VaultStoreErrorKind::OutcomeIndeterminate => {
                "the internal recovery storage outcome is indeterminate"
            }
        })
    }
}

impl Error for RecoveryOperationError {}

/// Recovery inventory policy over the same locked key and vault adapters.
pub(crate) struct RecoveryOperations<'dependencies, K, S> {
    keys: &'dependencies K,
    store: &'dependencies S,
}

impl<'dependencies, K, S> RecoveryOperations<'dependencies, K, S>
where
    K: KeyProvider,
    S: VaultStore,
{
    pub(crate) const fn new(keys: &'dependencies K, store: &'dependencies S) -> Self {
        Self { keys, store }
    }

    pub(crate) fn overview(&self) -> Result<RecoveryOverview, RecoveryOperationError> {
        self.store.shared_read(|read| {
            let purge_pending_count = read.read_recovery_purge_pending()?.len();
            Ok(RecoveryOverview {
                initialization_pending: read.read_init_pending()?.is_some(),
                rebuild_pending: read.read_rebuild_pending()?.is_some(),
                bundle_count: read.read_recovery_bundles()?.len(),
                purge_pending_count,
            })
        })
    }

    pub(crate) fn list(
        &self,
        interaction: InteractionPolicy,
    ) -> Result<RecoveryList, RecoveryOperationError> {
        self.store.shared_read(|read| {
            let mut bundles = read
                .read_recovery_bundles()?
                .into_iter()
                .map(|bundle| self.inspect_bundle(&bundle, interaction))
                .collect::<Vec<_>>();
            bundles.sort_by_key(|bundle| (bundle.created_at_unix_seconds, bundle.id));
            let mut purge_pending = read
                .read_recovery_purge_pending()?
                .into_iter()
                .map(|pending| pending.id)
                .collect::<Vec<_>>();
            purge_pending.sort_unstable();
            Ok(RecoveryList {
                bundles,
                purge_pending,
            })
        })
    }

    fn inspect_bundle(
        &self,
        bundle: &RecoveryBundle,
        interaction: InteractionPolicy,
    ) -> RecoveryInspection {
        let primary = bundle
            .live
            .as_deref()
            .or(bundle.init_pending.as_deref())
            .or(bundle.rebuild_pending.as_deref());
        let primary_metadata = primary.and_then(|envelope| inspect_envelope(envelope).ok());
        let authentication = [
            bundle.live.as_deref(),
            bundle.init_pending.as_deref(),
            bundle.rebuild_pending.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(|envelope| self.authenticate(envelope, interaction))
        .max_by_key(|status| status.exit_code())
        .unwrap_or(RecoveryAuthentication::Unreadable);

        RecoveryInspection {
            id: bundle.metadata.id,
            created_at_unix_seconds: bundle.metadata.created_at_unix_seconds,
            reason: bundle.metadata.reason,
            vault_id: primary_metadata.map(|metadata| metadata.vault_id),
            key_id: primary_metadata.map(|metadata| metadata.key_id),
            authentication,
        }
    }

    fn authenticate(
        &self,
        envelope: &[u8],
        interaction: InteractionPolicy,
    ) -> RecoveryAuthentication {
        let Ok(metadata) = inspect_envelope(envelope) else {
            return RecoveryAuthentication::Unreadable;
        };
        let key = match self.keys.load(&metadata.key_id, interaction) {
            Ok(key) => key,
            Err(error) => {
                return match error.kind() {
                    KeyProviderErrorKind::NotFound => RecoveryAuthentication::KeyMissing,
                    KeyProviderErrorKind::InvalidKeyMaterial => {
                        RecoveryAuthentication::InvalidKeyMaterial
                    }
                    KeyProviderErrorKind::AlreadyExists
                    | KeyProviderErrorKind::UserCancelled
                    | KeyProviderErrorKind::AuthenticationFailed
                    | KeyProviderErrorKind::InteractionRequired
                    | KeyProviderErrorKind::PermissionDenied
                    | KeyProviderErrorKind::Unavailable
                    | KeyProviderErrorKind::BackendFailure => {
                        RecoveryAuthentication::SecureStoreUnavailable
                    }
                };
            }
        };
        if open_envelope(envelope, &key).is_ok() {
            RecoveryAuthentication::Authenticated
        } else {
            RecoveryAuthentication::Unreadable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        init::Initializer,
        key_provider::KeyProviderErrorKind,
        testing::{MemoryKeyProvider, MemoryVaultStore, RecoveryPreservationFault},
        vault_store::{CommitOutcome, RecoveryArtifacts, RecoveryBundleMetadata, VaultStore},
    };

    const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;
    const BUNDLE_ID: RecoveryBundleId = RecoveryBundleId::from_bytes([7; 16]);

    fn initialized_recovery() -> (MemoryKeyProvider, MemoryVaultStore) {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let live = store.live().unwrap();
        store
            .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                assert_eq!(
                    transaction.preserve_recovery(
                        RecoveryBundleMetadata {
                            id: BUNDLE_ID,
                            created_at_unix_seconds: 1_765_000_000,
                            reason: RecoveryReason::Rebuild,
                        },
                        RecoveryArtifacts {
                            live: Some(&live),
                            init_pending: None,
                            rebuild_pending: None,
                        },
                    )?,
                    CommitOutcome::Committed
                );
                Ok(())
            })
            .unwrap();
        (keys, store)
    }

    #[test]
    fn lists_only_safe_authenticated_recovery_metadata() {
        let (keys, store) = initialized_recovery();
        let metadata = inspect_envelope(&store.live().unwrap()).unwrap();

        let list = RecoveryOperations::new(&keys, &store)
            .list(INTERACTION)
            .unwrap();

        assert_eq!(list.exit_code(), 0);
        assert_eq!(
            list.bundles,
            vec![RecoveryInspection {
                id: BUNDLE_ID,
                created_at_unix_seconds: 1_765_000_000,
                reason: RecoveryReason::Rebuild,
                vault_id: Some(metadata.vault_id),
                key_id: Some(metadata.key_id),
                authentication: RecoveryAuthentication::Authenticated,
            }]
        );
    }

    #[test]
    fn reports_keychain_failures_per_bundle_without_exposing_payload_names() {
        let (keys, store) = initialized_recovery();
        keys.fail_next_load(KeyProviderErrorKind::InteractionRequired);

        let list = RecoveryOperations::new(&keys, &store)
            .list(INTERACTION)
            .unwrap();

        assert_eq!(list.exit_code(), 11);
        assert_eq!(
            list.bundles[0].authentication,
            RecoveryAuthentication::SecureStoreUnavailable
        );
    }

    #[test]
    fn reports_a_definitively_missing_exact_bundle_key() {
        let (keys, store) = initialized_recovery();
        let metadata = inspect_envelope(&store.live().unwrap()).unwrap();
        keys.delete(&metadata.key_id, INTERACTION).unwrap();

        let list = RecoveryOperations::new(&keys, &store)
            .list(INTERACTION)
            .unwrap();

        assert_eq!(list.exit_code(), 12);
        assert_eq!(
            list.bundles[0].authentication,
            RecoveryAuthentication::KeyMissing
        );
    }

    #[test]
    fn overview_reports_reserved_initialization_and_bundle_state() {
        let (keys, store) = initialized_recovery();
        store.set_pending(b"opaque-conflicting-candidate".to_vec());
        store.set_rebuild_pending(b"opaque-rebuild-candidate".to_vec());

        assert_eq!(
            RecoveryOperations::new(&keys, &store).overview().unwrap(),
            RecoveryOverview {
                initialization_pending: true,
                rebuild_pending: true,
                bundle_count: 1,
                purge_pending_count: 0,
            }
        );
    }

    #[test]
    fn lists_staged_bundle_purges_separately_and_marks_recovery_actionable() {
        let (keys, store) = initialized_recovery();
        let key_id = inspect_envelope(&store.live().unwrap()).unwrap().key_id;
        store
            .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                assert_eq!(
                    transaction.stage_recovery_purge(BUNDLE_ID, &[key_id])?,
                    CommitOutcome::Committed
                );
                Ok(())
            })
            .unwrap();

        let operations = RecoveryOperations::new(&keys, &store);
        let list = operations.list(INTERACTION).unwrap();

        assert!(list.bundles.is_empty());
        assert_eq!(list.purge_pending, vec![BUNDLE_ID]);
        assert_eq!(list.exit_code(), 14);
        assert_eq!(
            operations.overview().unwrap(),
            RecoveryOverview {
                initialization_pending: false,
                rebuild_pending: false,
                bundle_count: 0,
                purge_pending_count: 1,
            }
        );
    }

    #[test]
    fn malformed_ciphertext_is_reported_without_guessing_identifiers() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        store
            .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                transaction.preserve_recovery(
                    RecoveryBundleMetadata {
                        id: BUNDLE_ID,
                        created_at_unix_seconds: 1_765_000_000,
                        reason: RecoveryReason::Restore,
                    },
                    RecoveryArtifacts {
                        live: Some(b"not-an-envelope"),
                        init_pending: None,
                        rebuild_pending: None,
                    },
                )?;
                Ok(())
            })
            .unwrap();

        let list = RecoveryOperations::new(&keys, &store)
            .list(INTERACTION)
            .unwrap();

        assert_eq!(list.exit_code(), 12);
        assert_eq!(list.bundles[0].vault_id, None);
        assert_eq!(list.bundles[0].key_id, None);
        assert_eq!(
            list.bundles[0].authentication,
            RecoveryAuthentication::Unreadable
        );
    }

    #[test]
    fn recovery_preservation_faults_distinguish_known_and_indeterminate_commits() {
        for (fault, expected_outcome, expected_count) in [
            (
                RecoveryPreservationFault::NotCommitted,
                CommitOutcome::NotCommitted,
                0,
            ),
            (
                RecoveryPreservationFault::IndeterminateBeforeCommit,
                CommitOutcome::Indeterminate,
                0,
            ),
            (
                RecoveryPreservationFault::IndeterminateAfterCommit,
                CommitOutcome::Indeterminate,
                1,
            ),
        ] {
            let keys = MemoryKeyProvider::new();
            let store = MemoryVaultStore::new();
            Initializer::new(&keys, &store)
                .initialize(INTERACTION)
                .unwrap();
            let live = store.live().unwrap();
            store.fail_next_recovery_preservation(fault);
            let outcome = store
                .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                    transaction.preserve_recovery(
                        RecoveryBundleMetadata {
                            id: BUNDLE_ID,
                            created_at_unix_seconds: 1,
                            reason: RecoveryReason::Restore,
                        },
                        RecoveryArtifacts {
                            live: Some(&live),
                            init_pending: None,
                            rebuild_pending: None,
                        },
                    )
                })
                .unwrap();
            assert_eq!(outcome, expected_outcome);
            let count = store
                .shared_read::<_, VaultStoreError, _>(|read| {
                    Ok(read.read_recovery_bundles()?.len())
                })
                .unwrap();
            assert_eq!(count, expected_count);
        }
    }
}
