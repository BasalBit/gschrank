#![forbid(unsafe_code)]

use std::{error::Error, fmt, time::SystemTime};

use crate::{
    KeyId, VaultId,
    confirmation::{ConfirmationError, TypedConfirmationRequest, TypedConfirmer},
    init::{InitError, InitOutcome, initialize_empty_locked},
    key_provider::{InteractionPolicy, KeyProvider},
    vault_store::{
        CommitOutcome, RecoveryArtifacts, RecoveryBundleId, RecoveryBundleMetadata, RecoveryReason,
        VaultStore, VaultStoreError, VaultStoreErrorKind, VaultTransaction,
    },
};

const MAX_RECOVERY_ID_ATTEMPTS: usize = 8;
const RESET_CONFIRMATION: TypedConfirmationRequest = TypedConfirmationRequest {
    expected: "RESET",
    action: "replace the current state with a new empty vault",
    warning: "The current encrypted vault and any pending lifecycle state will be retained as an internal recovery bundle. Existing Keychain items and external backups will not be deleted.",
};

/// A safe failure supplied by the caller while preparing dependent state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResetPreparationError {
    exit_code: u8,
}

impl ResetPreparationError {
    pub(crate) const fn new(exit_code: u8) -> Self {
        Self { exit_code }
    }

    pub(crate) const fn exit_code(self) -> u8 {
        self.exit_code
    }
}

/// Safe metadata for a completed recoverable reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResetReceipt {
    pub(crate) vault_id: VaultId,
    pub(crate) key_id: KeyId,
    pub(crate) recovery_bundle: RecoveryBundleId,
}

/// Value- and name-free recoverable-reset failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResetError {
    NotInitialized,
    Confirmation(ConfirmationError),
    PreparationFailed(ResetPreparationError),
    Store(VaultStoreError),
    RecoveryNotCommitted,
    RecoveryOutcomeIndeterminate,
    RootClearNotCommitted,
    RootClearOutcomeIndeterminate,
    Initialization(InitError),
}

impl ResetError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::NotInitialized => 10,
            Self::Confirmation(error) => error.exit_code(),
            Self::PreparationFailed(error) => error.exit_code(),
            Self::Store(error) => match error.kind() {
                VaultStoreErrorKind::UnsafePath
                | VaultStoreErrorKind::PermissionDenied
                | VaultStoreErrorKind::UnsupportedStorage => 13,
                VaultStoreErrorKind::Conflict => 14,
                VaultStoreErrorKind::OutcomeIndeterminate => 15,
                VaultStoreErrorKind::MissingState
                | VaultStoreErrorKind::LockFailure
                | VaultStoreErrorKind::IoFailure => 1,
            },
            Self::RecoveryNotCommitted | Self::RootClearNotCommitted => 1,
            Self::RecoveryOutcomeIndeterminate | Self::RootClearOutcomeIndeterminate => 15,
            Self::Initialization(error) => error.exit_code(),
        }
    }
}

impl From<VaultStoreError> for ResetError {
    fn from(error: VaultStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<ConfirmationError> for ResetError {
    fn from(error: ConfirmationError) -> Self {
        Self::Confirmation(error)
    }
}

impl From<InitError> for ResetError {
    fn from(error: InitError) -> Self {
        Self::Initialization(error)
    }
}

impl fmt::Display for ResetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => formatter
                .write_str("there is no live or pending vault state to reset; use 'gschrank init'"),
            Self::Confirmation(error) => error.fmt(formatter),
            Self::PreparationFailed(_) => formatter.write_str(
                "automatic startup loading could not be disabled; vault reset did not begin",
            ),
            Self::Store(_) => formatter.write_str("the local vault or recovery store failed"),
            Self::RecoveryNotCommitted => formatter
                .write_str("the current vault state could not be preserved; nothing was removed"),
            Self::RecoveryOutcomeIndeterminate => formatter.write_str(
                "recovery preservation is indeterminate; the current vault state was not removed",
            ),
            Self::RootClearNotCommitted => formatter.write_str(
                "the preserved vault state could not be detached from the live location",
            ),
            Self::RootClearOutcomeIndeterminate => formatter.write_str(
                "vault reset is indeterminate; inspect recovery and live state before retrying",
            ),
            Self::Initialization(error) => {
                write!(formatter, "the previous state was preserved, but {error}")
            }
        }
    }
}

impl Error for ResetError {}

/// Recoverable empty-vault reset policy over portable storage and key seams.
pub(crate) struct ResetOperations<'dependencies, K, S> {
    keys: &'dependencies K,
    store: &'dependencies S,
}

impl<'dependencies, K, S> ResetOperations<'dependencies, K, S>
where
    K: KeyProvider,
    S: VaultStore,
{
    pub(crate) const fn new(keys: &'dependencies K, store: &'dependencies S) -> Self {
        Self { keys, store }
    }

    /// Confirm, prepare dependent shell state, preserve the exact old state,
    /// detach it, and initialize an independently keyed empty vault while one
    /// exclusive store lock is retained.
    pub(crate) fn reset<F>(
        &self,
        interaction: InteractionPolicy,
        confirmer: &mut dyn TypedConfirmer,
        prepare: F,
    ) -> Result<ResetReceipt, ResetError>
    where
        F: FnOnce() -> Result<(), ResetPreparationError>,
    {
        self.store.exclusive_transaction(|transaction| {
            let live = transaction.read_live()?;
            let init_pending = transaction.read_init_pending()?;
            let rebuild_pending = transaction.read_rebuild_pending()?;
            if live.is_none() && init_pending.is_none() && rebuild_pending.is_none() {
                return Err(ResetError::NotInitialized);
            }

            confirmer.confirm(RESET_CONFIRMATION)?;
            prepare().map_err(ResetError::PreparationFailed)?;

            let recovery_bundle = Self::preserve_root(
                transaction,
                live.as_ref().map(|bytes| bytes.as_slice()),
                init_pending.as_ref().map(|bytes| bytes.as_slice()),
                rebuild_pending.as_ref().map(|bytes| bytes.as_slice()),
            )?;
            Self::clear_preserved_root(transaction)?;
            let InitOutcome::Created { vault_id, key_id } =
                initialize_empty_locked(self.keys, transaction, interaction)?
            else {
                return Err(ResetError::RootClearOutcomeIndeterminate);
            };

            Ok(ResetReceipt {
                vault_id,
                key_id,
                recovery_bundle,
            })
        })
    }

    fn preserve_root(
        transaction: &mut dyn VaultTransaction,
        live: Option<&[u8]>,
        init_pending: Option<&[u8]>,
        rebuild_pending: Option<&[u8]>,
    ) -> Result<RecoveryBundleId, ResetError> {
        let created_at_unix_seconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::IoFailure))?
            .as_secs();
        for _ in 0..MAX_RECOVERY_ID_ATTEMPTS {
            let metadata = RecoveryBundleMetadata {
                id: RecoveryBundleId::generate()?,
                created_at_unix_seconds,
                reason: RecoveryReason::Reset,
            };
            let outcome = match transaction.preserve_recovery(
                metadata,
                RecoveryArtifacts {
                    live,
                    init_pending,
                    rebuild_pending,
                },
            ) {
                Err(error) if error.kind() == VaultStoreErrorKind::Conflict => continue,
                result => result?,
            };
            match outcome {
                CommitOutcome::NotCommitted => return Err(ResetError::RecoveryNotCommitted),
                CommitOutcome::Indeterminate => {
                    return Err(ResetError::RecoveryOutcomeIndeterminate);
                }
                CommitOutcome::Committed => {}
            }

            let preserved = transaction
                .read_recovery_bundles()?
                .into_iter()
                .find(|bundle| bundle.metadata.id == metadata.id);
            if preserved.is_some_and(|bundle| {
                bundle.metadata == metadata
                    && optional_bytes_equal(
                        bundle.live.as_ref().map(|bytes| bytes.as_slice()),
                        live,
                    )
                    && optional_bytes_equal(
                        bundle.init_pending.as_ref().map(|bytes| bytes.as_slice()),
                        init_pending,
                    )
                    && optional_bytes_equal(
                        bundle
                            .rebuild_pending
                            .as_ref()
                            .map(|bytes| bytes.as_slice()),
                        rebuild_pending,
                    )
            }) {
                return Ok(metadata.id);
            }
            return Err(ResetError::RecoveryOutcomeIndeterminate);
        }
        Err(VaultStoreError::new(VaultStoreErrorKind::Conflict).into())
    }

    fn clear_preserved_root(transaction: &mut dyn VaultTransaction) -> Result<(), ResetError> {
        let outcome = transaction.clear_root_artifacts()?;
        let root_is_absent = transaction.read_live()?.is_none()
            && transaction.read_init_pending()?.is_none()
            && transaction.read_rebuild_pending()?.is_none();
        match (outcome, root_is_absent) {
            (CommitOutcome::Committed | CommitOutcome::Indeterminate, true) => Ok(()),
            (CommitOutcome::NotCommitted, _) => Err(ResetError::RootClearNotCommitted),
            (CommitOutcome::Committed | CommitOutcome::Indeterminate, false) => {
                Err(ResetError::RootClearOutcomeIndeterminate)
            }
        }
    }
}

fn optional_bytes_equal(left: Option<&[u8]>, right: Option<&[u8]>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EnvironmentName, ProfileName, SecretValue, inspect_envelope, open_envelope,
        profiles::ProfileOperations,
        testing::{MemoryKeyProvider, MemoryVaultStore, RecoveryPreservationFault, RootClearFault},
        vault_store::VaultStore,
    };

    const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;

    struct ScriptedConfirmer {
        result: Result<(), ConfirmationError>,
        calls: usize,
    }

    impl ScriptedConfirmer {
        fn accepting() -> Self {
            Self {
                result: Ok(()),
                calls: 0,
            }
        }

        fn rejecting() -> Self {
            Self {
                result: Err(ConfirmationError::Rejected),
                calls: 0,
            }
        }
    }

    impl TypedConfirmer for ScriptedConfirmer {
        fn confirm(&mut self, request: TypedConfirmationRequest) -> Result<(), ConfirmationError> {
            self.calls += 1;
            assert_eq!(request.expected, "RESET");
            assert!(!request.warning.contains("CANARY"));
            self.result
        }
    }

    fn initialized_with_secret() -> (MemoryKeyProvider, MemoryVaultStore, KeyId, Vec<u8>) {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        crate::init::Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let old_key_id = inspect_envelope(&store.live().unwrap()).unwrap().key_id;
        let profile = ProfileName::new("work").unwrap();
        let operations = ProfileOperations::new(&keys, &store);
        operations.create(profile.clone(), INTERACTION).unwrap();
        operations
            .set(
                &profile,
                EnvironmentName::new("TOKEN").unwrap(),
                SecretValue::from_string("CANARY-reset-secret".to_owned()).unwrap(),
                INTERACTION,
            )
            .unwrap();
        let old_live = store.live().unwrap();
        (keys, store, old_key_id, old_live)
    }

    #[test]
    fn reset_preserves_exact_old_state_and_creates_an_independently_keyed_empty_vault() {
        let (keys, store, old_key_id, old_live) = initialized_with_secret();
        let mut confirmer = ScriptedConfirmer::accepting();
        let mut prepared = false;

        let receipt = ResetOperations::new(&keys, &store)
            .reset(INTERACTION, &mut confirmer, || {
                prepared = true;
                Ok(())
            })
            .unwrap();

        assert!(prepared);
        assert_eq!(confirmer.calls, 1);
        assert_ne!(receipt.key_id, old_key_id);
        assert!(keys.contains(&old_key_id));
        assert!(keys.contains(&receipt.key_id));
        assert_eq!(keys.key_count(), 2);
        assert!(store.pending().is_none());

        let live = store.live().unwrap();
        let new_key = keys.load(&receipt.key_id, INTERACTION).unwrap();
        let opened = open_envelope(&live, &new_key).unwrap();
        assert_eq!(opened.vault_id, receipt.vault_id);
        assert_eq!(opened.vault.revision(), 0);
        assert_eq!(opened.vault.profile_names().len(), 0);

        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].metadata.id, receipt.recovery_bundle);
        assert_eq!(bundles[0].metadata.reason, RecoveryReason::Reset);
        assert_eq!(
            bundles[0].live.as_ref().map(|bytes| bytes.as_slice()),
            Some(old_live.as_slice())
        );
        assert!(bundles[0].init_pending.is_none());
    }

    #[test]
    fn reset_preserves_unreadable_live_and_conflicting_pending_bytes_without_key_access() {
        let (keys, store, old_key_id, _) = initialized_with_secret();
        let live = b"CANARY-unreadable-live".to_vec();
        let pending = b"CANARY-unreadable-pending".to_vec();
        let rebuild = b"CANARY-unreadable-rebuild".to_vec();
        store.set_live(live.clone());
        store.set_pending(pending.clone());
        store.set_rebuild_pending(rebuild.clone());
        keys.fail_next_load(crate::key_provider::KeyProviderErrorKind::BackendFailure);
        let mut confirmer = ScriptedConfirmer::accepting();

        let receipt = ResetOperations::new(&keys, &store)
            .reset(INTERACTION, &mut confirmer, || Ok(()))
            .unwrap();

        assert!(keys.contains(&old_key_id));
        assert!(keys.contains(&receipt.key_id));
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(
            bundles[0].live.as_ref().map(|bytes| bytes.as_slice()),
            Some(live.as_slice())
        );
        assert_eq!(
            bundles[0]
                .init_pending
                .as_ref()
                .map(|bytes| bytes.as_slice()),
            Some(pending.as_slice())
        );
        assert_eq!(
            bundles[0]
                .rebuild_pending
                .as_ref()
                .map(|bytes| bytes.as_slice()),
            Some(rebuild.as_slice())
        );
    }

    #[test]
    fn absent_state_and_rejected_confirmation_do_not_prepare_or_mutate() {
        let keys = MemoryKeyProvider::new();
        let empty = MemoryVaultStore::new();
        let mut confirmer = ScriptedConfirmer::accepting();
        let mut prepared = false;
        let error = ResetOperations::new(&keys, &empty)
            .reset(INTERACTION, &mut confirmer, || {
                prepared = true;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error, ResetError::NotInitialized);
        assert_eq!(confirmer.calls, 0);
        assert!(!prepared);

        let (keys, store, _, old_live) = initialized_with_secret();
        let mut confirmer = ScriptedConfirmer::rejecting();
        let error = ResetOperations::new(&keys, &store)
            .reset(INTERACTION, &mut confirmer, || {
                prepared = true;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error, ResetError::Confirmation(ConfirmationError::Rejected));
        assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
        assert!(!prepared);
    }

    #[test]
    fn preparation_or_recovery_failure_leaves_root_state_exactly_unchanged() {
        let (keys, store, _, old_live) = initialized_with_secret();
        let mut confirmer = ScriptedConfirmer::accepting();
        let error = ResetOperations::new(&keys, &store)
            .reset(INTERACTION, &mut confirmer, || {
                Err(ResetPreparationError::new(13))
            })
            .unwrap_err();
        assert_eq!(error.exit_code(), 13);
        assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));

        for fault in [
            RecoveryPreservationFault::NotCommitted,
            RecoveryPreservationFault::IndeterminateBeforeCommit,
            RecoveryPreservationFault::IndeterminateAfterCommit,
        ] {
            let (keys, store, _, old_live) = initialized_with_secret();
            store.fail_next_recovery_preservation(fault);
            let mut confirmer = ScriptedConfirmer::accepting();
            assert!(
                ResetOperations::new(&keys, &store)
                    .reset(INTERACTION, &mut confirmer, || Ok(()))
                    .is_err()
            );
            assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
        }
    }

    #[test]
    fn indeterminate_root_clear_proceeds_only_when_both_root_artifacts_are_absent() {
        for fault in [
            RootClearFault::NotCommitted,
            RootClearFault::IndeterminateBeforeCommit,
        ] {
            let (keys, store, _, old_live) = initialized_with_secret();
            store.fail_next_root_clear(fault);
            let mut confirmer = ScriptedConfirmer::accepting();
            let error = ResetOperations::new(&keys, &store)
                .reset(INTERACTION, &mut confirmer, || Ok(()))
                .unwrap_err();
            assert!(matches!(
                error,
                ResetError::RootClearNotCommitted | ResetError::RootClearOutcomeIndeterminate
            ));
            assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
            assert_eq!(keys.key_count(), 1);
        }

        let (keys, store, _, old_live) = initialized_with_secret();
        store.fail_next_root_clear(RootClearFault::IndeterminateAfterCommit);
        let mut confirmer = ScriptedConfirmer::accepting();
        let receipt = ResetOperations::new(&keys, &store)
            .reset(INTERACTION, &mut confirmer, || Ok(()))
            .unwrap();
        assert!(keys.contains(&receipt.key_id));
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(
            bundles[0].live.as_ref().map(|bytes| bytes.as_slice()),
            Some(old_live.as_slice())
        );
    }

    #[test]
    fn failed_fresh_initialization_keeps_the_old_recovery_escape_hatch() {
        let (keys, store, old_key_id, old_live) = initialized_with_secret();
        keys.fail_next_store(crate::key_provider::KeyProviderErrorKind::UserCancelled);
        let mut confirmer = ScriptedConfirmer::accepting();
        let error = ResetOperations::new(&keys, &store)
            .reset(INTERACTION, &mut confirmer, || Ok(()))
            .unwrap_err();

        assert!(matches!(error, ResetError::Initialization(_)));
        assert!(store.live().is_none());
        assert!(store.pending().is_none());
        assert!(keys.contains(&old_key_id));
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(
            bundles[0].live.as_ref().map(|bytes| bytes.as_slice()),
            Some(old_live.as_slice())
        );
        assert!(!error.to_string().contains("CANARY"));
    }
}
