#![forbid(unsafe_code)]

use std::{collections::BTreeSet, error::Error, fmt};

use crate::{
    EnvelopeError, KeyId,
    confirmation::{ConfirmationError, TypedConfirmationRequest, TypedConfirmer},
    inspect_envelope,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderError, KeyProviderErrorKind},
    open_envelope,
    vault_store::{
        CommitOutcome, RecoveryBundle, RecoveryBundleId, RecoveryPurgePending, VaultStore,
        VaultStoreError, VaultStoreErrorKind, VaultTransaction,
    },
};

const PURGE_CONFIRMATION: TypedConfirmationRequest = TypedConfirmationRequest {
    expected: "PURGE",
    action: "purge the selected internal recovery bundle",
    warning: "The selected encrypted recovery bundle will be permanently removed. Any Keychain item used only by this bundle will also be deleted, which can make external backups unreadable.",
};

/// Safe metadata for one completed recovery-bundle purge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryPurgeReceipt {
    pub(crate) bundle_id: RecoveryBundleId,
    pub(crate) retired_key_count: usize,
    pub(crate) retained_key_count: usize,
}

/// Value- and name-free recovery-bundle purge failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryPurgeError {
    BundleNotFound,
    AnotherPurgePending(RecoveryBundleId),
    PendingStateUnreadable,
    ReferenceStateUnreadable,
    Confirmation(ConfirmationError),
    SecureStore(KeyProviderError),
    VaultKeyMissing,
    InvalidKeyMaterial,
    Vault(EnvelopeError),
    Store(VaultStoreError),
    StageNotCommitted,
    StageOutcomeIndeterminate,
    CleanupNotCommitted,
    CleanupOutcomeIndeterminate,
}

impl RecoveryPurgeError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::BundleNotFound
            | Self::AnotherPurgePending(_)
            | Self::PendingStateUnreadable
            | Self::ReferenceStateUnreadable => 14,
            Self::Confirmation(error) => error.exit_code(),
            Self::SecureStore(_) => 11,
            Self::VaultKeyMissing | Self::InvalidKeyMaterial | Self::Vault(_) => 12,
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
            Self::StageNotCommitted | Self::CleanupNotCommitted => 1,
            Self::StageOutcomeIndeterminate | Self::CleanupOutcomeIndeterminate => 15,
        }
    }

    fn from_key_provider(error: KeyProviderError) -> Self {
        match error.kind() {
            KeyProviderErrorKind::NotFound => Self::VaultKeyMissing,
            KeyProviderErrorKind::InvalidKeyMaterial => Self::InvalidKeyMaterial,
            KeyProviderErrorKind::AlreadyExists
            | KeyProviderErrorKind::UserCancelled
            | KeyProviderErrorKind::AuthenticationFailed
            | KeyProviderErrorKind::InteractionRequired
            | KeyProviderErrorKind::PermissionDenied
            | KeyProviderErrorKind::Unavailable
            | KeyProviderErrorKind::BackendFailure => Self::SecureStore(error),
        }
    }
}

impl From<ConfirmationError> for RecoveryPurgeError {
    fn from(error: ConfirmationError) -> Self {
        Self::Confirmation(error)
    }
}

impl From<VaultStoreError> for RecoveryPurgeError {
    fn from(error: VaultStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<EnvelopeError> for RecoveryPurgeError {
    fn from(error: EnvelopeError) -> Self {
        Self::Vault(error)
    }
}

impl fmt::Display for RecoveryPurgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BundleNotFound => formatter.write_str("the recovery bundle does not exist"),
            Self::AnotherPurgePending(id) => write!(
                formatter,
                "recovery bundle {} already has a purge pending; resume it first",
                id.to_hex()
            ),
            Self::PendingStateUnreadable => formatter.write_str(
                "the staged recovery purge cannot be authenticated or resumed safely",
            ),
            Self::ReferenceStateUnreadable => formatter.write_str(
                "another encrypted artifact is unreadable, so Keychain references cannot be checked safely",
            ),
            Self::Confirmation(error) => error.fmt(formatter),
            Self::SecureStore(_) => formatter.write_str("secure-store access failed"),
            Self::VaultKeyMissing => {
                formatter.write_str("a recovery bundle's secure-store key is missing")
            }
            Self::InvalidKeyMaterial => {
                formatter.write_str("a recovery bundle's secure-store key is invalid")
            }
            Self::Vault(_) => formatter.write_str("the encrypted recovery bundle is unreadable"),
            Self::Store(_) => formatter.write_str("the local recovery store failed"),
            Self::StageNotCommitted => formatter.write_str(
                "the recovery bundle was not staged; no Keychain item was deleted",
            ),
            Self::StageOutcomeIndeterminate => formatter.write_str(
                "recovery purge staging is indeterminate; inspect recovery state before retrying",
            ),
            Self::CleanupNotCommitted => formatter.write_str(
                "the Keychain operation completed but staged recovery ciphertext remains",
            ),
            Self::CleanupOutcomeIndeterminate => formatter.write_str(
                "recovery purge cleanup is indeterminate; inspect recovery state before retrying",
            ),
        }
    }
}

impl Error for RecoveryPurgeError {}

/// Authenticated, reference-aware, crash-resumable recovery-bundle deletion.
pub(crate) struct RecoveryPurgeOperations<'dependencies, K, S> {
    keys: &'dependencies K,
    store: &'dependencies S,
}

impl<'dependencies, K, S> RecoveryPurgeOperations<'dependencies, K, S>
where
    K: KeyProvider,
    S: VaultStore,
{
    pub(crate) const fn new(keys: &'dependencies K, store: &'dependencies S) -> Self {
        Self { keys, store }
    }

    pub(crate) fn purge(
        &self,
        bundle_id: RecoveryBundleId,
        interaction: InteractionPolicy,
        confirmer: &mut dyn TypedConfirmer,
    ) -> Result<RecoveryPurgeReceipt, RecoveryPurgeError> {
        self.store.exclusive_transaction(|transaction| {
            let pending = transaction.read_recovery_purge_pending()?;
            if let Some(other) = pending.iter().find(|pending| pending.id != bundle_id) {
                return Err(RecoveryPurgeError::AnotherPurgePending(other.id));
            }
            let selected_pending = pending.into_iter().find(|pending| pending.id == bundle_id);
            let active = transaction
                .read_recovery_bundles()?
                .into_iter()
                .find(|bundle| bundle.metadata.id == bundle_id);
            if selected_pending.is_some() && active.is_some() {
                return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict).into());
            }

            let (key_ids, needs_staging) = match (selected_pending, active) {
                (Some(pending), None) => self.resume_plan(pending, interaction)?,
                (None, Some(bundle)) => (self.authenticate_bundle(&bundle, interaction)?, true),
                (None, None) => return Err(RecoveryPurgeError::BundleNotFound),
                (Some(_), Some(_)) => unreachable!("conflict handled above"),
            };

            confirmer.confirm(PURGE_CONFIRMATION)?;
            let referenced = Self::referenced_elsewhere(transaction, bundle_id, &key_ids)?;
            if needs_staging {
                Self::stage_and_verify(transaction, bundle_id, &key_ids)?;
            }

            let mut retired_key_count = 0;
            let mut retained_key_count = 0;
            for key_id in &key_ids {
                if referenced.contains(key_id) {
                    retained_key_count += 1;
                    continue;
                }
                match self.keys.delete(key_id, interaction) {
                    Ok(()) => {
                        retired_key_count += 1;
                    }
                    Err(error) if error.kind() == KeyProviderErrorKind::NotFound => {
                        retired_key_count += 1;
                    }
                    Err(error) => return Err(RecoveryPurgeError::from_key_provider(error)),
                }
            }

            Self::remove_staged_and_verify(transaction, bundle_id)?;
            Ok(RecoveryPurgeReceipt {
                bundle_id,
                retired_key_count,
                retained_key_count,
            })
        })
    }

    fn resume_plan(
        &self,
        pending: RecoveryPurgePending,
        interaction: InteractionPolicy,
    ) -> Result<(Vec<KeyId>, bool), RecoveryPurgeError> {
        if let Some(key_ids) = pending.key_ids {
            return Ok((key_ids, pending.bundle.is_some()));
        }
        let bundle = pending
            .bundle
            .ok_or(RecoveryPurgeError::PendingStateUnreadable)?;
        Ok((self.authenticate_bundle(&bundle, interaction)?, true))
    }

    fn authenticate_bundle(
        &self,
        bundle: &RecoveryBundle,
        interaction: InteractionPolicy,
    ) -> Result<Vec<KeyId>, RecoveryPurgeError> {
        let mut key_ids = BTreeSet::new();
        let mut found = false;
        for envelope in bundle_artifacts(bundle) {
            found = true;
            let metadata = inspect_envelope(envelope)?;
            let key = self
                .keys
                .load(&metadata.key_id, interaction)
                .map_err(RecoveryPurgeError::from_key_provider)?;
            let opened = open_envelope(envelope, &key)?;
            if opened.key_id != metadata.key_id || opened.vault_id != metadata.vault_id {
                return Err(RecoveryPurgeError::Vault(
                    EnvelopeError::AuthenticationFailed,
                ));
            }
            key_ids.insert(metadata.key_id);
        }
        if !found {
            return Err(RecoveryPurgeError::PendingStateUnreadable);
        }
        Ok(key_ids.into_iter().collect())
    }

    fn referenced_elsewhere(
        transaction: &mut dyn VaultTransaction,
        selected_id: RecoveryBundleId,
        selected_keys: &[KeyId],
    ) -> Result<BTreeSet<KeyId>, RecoveryPurgeError> {
        let selected = selected_keys.iter().copied().collect::<BTreeSet<_>>();
        let mut referenced = BTreeSet::new();
        for envelope in [
            transaction.read_live()?,
            transaction.read_init_pending()?,
            transaction.read_rebuild_pending()?,
        ]
        .into_iter()
        .flatten()
        {
            Self::record_reference(&envelope, &selected, &mut referenced)?;
        }
        for bundle in transaction.read_recovery_bundles()? {
            if bundle.metadata.id == selected_id {
                continue;
            }
            for envelope in bundle_artifacts(&bundle) {
                Self::record_reference(envelope, &selected, &mut referenced)?;
            }
        }
        Ok(referenced)
    }

    fn record_reference(
        envelope: &[u8],
        selected: &BTreeSet<KeyId>,
        referenced: &mut BTreeSet<KeyId>,
    ) -> Result<(), RecoveryPurgeError> {
        let metadata =
            inspect_envelope(envelope).map_err(|_| RecoveryPurgeError::ReferenceStateUnreadable)?;
        if selected.contains(&metadata.key_id) {
            referenced.insert(metadata.key_id);
        }
        Ok(())
    }

    fn stage_and_verify(
        transaction: &mut dyn VaultTransaction,
        bundle_id: RecoveryBundleId,
        key_ids: &[KeyId],
    ) -> Result<(), RecoveryPurgeError> {
        let outcome = transaction.stage_recovery_purge(bundle_id, key_ids)?;
        let exact_plan = transaction
            .read_recovery_purge_pending()?
            .into_iter()
            .find(|pending| pending.id == bundle_id)
            .is_some_and(|pending| pending.key_ids.as_deref() == Some(key_ids));
        if outcome == CommitOutcome::Committed && exact_plan {
            return Ok(());
        }
        Err(match outcome {
            CommitOutcome::NotCommitted if !exact_plan => RecoveryPurgeError::StageNotCommitted,
            CommitOutcome::NotCommitted
            | CommitOutcome::Committed
            | CommitOutcome::Indeterminate => RecoveryPurgeError::StageOutcomeIndeterminate,
        })
    }

    fn remove_staged_and_verify(
        transaction: &mut dyn VaultTransaction,
        bundle_id: RecoveryBundleId,
    ) -> Result<(), RecoveryPurgeError> {
        let outcome = transaction.remove_recovery_purge_pending(bundle_id)?;
        let absent = transaction
            .read_recovery_purge_pending()?
            .into_iter()
            .all(|pending| pending.id != bundle_id);
        if absent {
            return Ok(());
        }
        Err(match outcome {
            CommitOutcome::NotCommitted => RecoveryPurgeError::CleanupNotCommitted,
            CommitOutcome::Committed | CommitOutcome::Indeterminate => {
                RecoveryPurgeError::CleanupOutcomeIndeterminate
            }
        })
    }
}

fn bundle_artifacts(bundle: &RecoveryBundle) -> impl Iterator<Item = &[u8]> {
    [
        bundle.live.as_ref().map(|bytes| bytes.as_slice()),
        bundle.init_pending.as_ref().map(|bytes| bytes.as_slice()),
        bundle
            .rebuild_pending
            .as_ref()
            .map(|bytes| bytes.as_slice()),
    ]
    .into_iter()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EnvironmentName, MasterKey, ProfileName, SecretValue, Vault, VaultId,
        confirmation::TypedConfirmationRequest,
        init::Initializer,
        seal_vault,
        testing::{
            MemoryKeyProvider, MemoryVaultStore, RecoveryPurgeRemovalFault, RecoveryPurgeStageFault,
        },
        vault_store::{RecoveryArtifacts, RecoveryBundleMetadata, RecoveryReason, VaultStore},
    };

    const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;
    const BUNDLE_ID: RecoveryBundleId = RecoveryBundleId::from_bytes([7; 16]);
    const OTHER_BUNDLE_ID: RecoveryBundleId = RecoveryBundleId::from_bytes([8; 16]);

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
    }

    impl TypedConfirmer for ScriptedConfirmer {
        fn confirm(&mut self, request: TypedConfirmationRequest) -> Result<(), ConfirmationError> {
            self.calls += 1;
            assert_eq!(request.expected, "PURGE");
            assert!(request.warning.contains("external backups"));
            assert!(!request.warning.contains("CANARY"));
            self.result
        }
    }

    fn initialized() -> (MemoryKeyProvider, MemoryVaultStore, KeyId) {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let live = store.live().unwrap();
        let live_key_id = inspect_envelope(&live).unwrap().key_id;
        (keys, store, live_key_id)
    }

    fn standalone_envelope(keys: &MemoryKeyProvider, marker: u8) -> (KeyId, Vec<u8>) {
        let key_id = KeyId::from_bytes([marker; 16]);
        let key = MasterKey::from_bytes([marker.wrapping_add(1); 32]);
        keys.insert(key_id, &key);
        let mut vault = Vault::empty();
        let profile = ProfileName::new("private").unwrap();
        vault.create_profile(profile.clone()).unwrap();
        vault
            .set(
                &profile,
                EnvironmentName::new("TOKEN").unwrap(),
                SecretValue::from_string("CANARY-purge-secret".to_owned()).unwrap(),
            )
            .unwrap();
        let envelope = seal_vault(
            &vault,
            VaultId::from_bytes([marker.wrapping_add(2); 16]),
            key_id,
            &key,
        )
        .unwrap();
        (key_id, envelope.to_vec())
    }

    fn preserve(store: &MemoryVaultStore, id: RecoveryBundleId, envelope: &[u8]) {
        store
            .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                transaction.preserve_recovery(
                    RecoveryBundleMetadata {
                        id,
                        created_at_unix_seconds: 1_765_000_000,
                        reason: RecoveryReason::Rebuild,
                    },
                    RecoveryArtifacts {
                        live: Some(envelope),
                        init_pending: None,
                        rebuild_pending: None,
                    },
                )?;
                Ok(())
            })
            .unwrap();
    }

    fn recovery_counts(store: &MemoryVaultStore) -> (usize, usize) {
        store
            .shared_read::<_, VaultStoreError, _>(|read| {
                Ok((
                    read.read_recovery_bundles()?.len(),
                    read.read_recovery_purge_pending()?.len(),
                ))
            })
            .unwrap()
    }

    #[test]
    fn purges_an_unshared_authenticated_bundle_and_its_exact_key() {
        let (keys, store, live_key_id) = initialized();
        let (old_key_id, envelope) = standalone_envelope(&keys, 3);
        preserve(&store, BUNDLE_ID, &envelope);
        let mut confirmer = ScriptedConfirmer::accepting();

        let receipt = RecoveryPurgeOperations::new(&keys, &store)
            .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(confirmer.calls, 1);
        assert_eq!(receipt.bundle_id, BUNDLE_ID);
        assert_eq!(receipt.retired_key_count, 1);
        assert_eq!(receipt.retained_key_count, 0);
        assert!(!keys.contains(&old_key_id));
        assert!(keys.contains(&live_key_id));
        assert_eq!(recovery_counts(&store), (0, 0));
    }

    #[test]
    fn purges_ciphertext_but_retains_a_key_referenced_by_the_live_vault() {
        let (keys, store, live_key_id) = initialized();
        let live = store.live().unwrap();
        preserve(&store, BUNDLE_ID, &live);
        let mut confirmer = ScriptedConfirmer::accepting();

        let receipt = RecoveryPurgeOperations::new(&keys, &store)
            .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(receipt.retired_key_count, 0);
        assert_eq!(receipt.retained_key_count, 1);
        assert!(keys.contains(&live_key_id));
        assert_eq!(recovery_counts(&store), (0, 0));
    }

    #[test]
    fn another_recovery_reference_also_retains_the_shared_key() {
        let (keys, store, _) = initialized();
        let (old_key_id, envelope) = standalone_envelope(&keys, 3);
        preserve(&store, BUNDLE_ID, &envelope);
        preserve(&store, OTHER_BUNDLE_ID, &envelope);
        let mut confirmer = ScriptedConfirmer::accepting();

        let receipt = RecoveryPurgeOperations::new(&keys, &store)
            .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(receipt.retained_key_count, 1);
        assert!(keys.contains(&old_key_id));
        assert_eq!(recovery_counts(&store), (1, 0));
    }

    #[test]
    fn retires_only_unshared_keys_from_a_bundle_with_multiple_artifacts() {
        let (keys, store, live_key_id) = initialized();
        let live = store.live().unwrap();
        let (old_key_id, old_envelope) = standalone_envelope(&keys, 3);
        store
            .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                transaction.preserve_recovery(
                    RecoveryBundleMetadata {
                        id: BUNDLE_ID,
                        created_at_unix_seconds: 1_765_000_000,
                        reason: RecoveryReason::Reset,
                    },
                    RecoveryArtifacts {
                        live: Some(&old_envelope),
                        init_pending: Some(&live),
                        rebuild_pending: None,
                    },
                )?;
                Ok(())
            })
            .unwrap();
        let mut confirmer = ScriptedConfirmer::accepting();

        let receipt = RecoveryPurgeOperations::new(&keys, &store)
            .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(receipt.retired_key_count, 1);
        assert_eq!(receipt.retained_key_count, 1);
        assert!(!keys.contains(&old_key_id));
        assert!(keys.contains(&live_key_id));
        assert_eq!(recovery_counts(&store), (0, 0));
    }

    #[test]
    fn unreadable_other_artifacts_block_reference_sensitive_key_deletion() {
        let (keys, store, _) = initialized();
        let (old_key_id, envelope) = standalone_envelope(&keys, 3);
        preserve(&store, BUNDLE_ID, &envelope);
        preserve(&store, OTHER_BUNDLE_ID, b"CANARY-unreadable-other-bundle");
        let mut confirmer = ScriptedConfirmer::accepting();

        assert_eq!(
            RecoveryPurgeOperations::new(&keys, &store)
                .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
                .unwrap_err(),
            RecoveryPurgeError::ReferenceStateUnreadable
        );
        assert!(keys.contains(&old_key_id));
        assert_eq!(recovery_counts(&store), (2, 0));
    }

    #[test]
    fn rejection_and_unreadable_ciphertext_never_stage_or_delete() {
        let (keys, store, _) = initialized();
        let (old_key_id, envelope) = standalone_envelope(&keys, 3);
        preserve(&store, BUNDLE_ID, &envelope);
        let mut rejected = ScriptedConfirmer {
            result: Err(ConfirmationError::Rejected),
            calls: 0,
        };
        assert_eq!(
            RecoveryPurgeOperations::new(&keys, &store)
                .purge(BUNDLE_ID, INTERACTION, &mut rejected)
                .unwrap_err(),
            RecoveryPurgeError::Confirmation(ConfirmationError::Rejected)
        );
        assert!(keys.contains(&old_key_id));
        assert_eq!(recovery_counts(&store), (1, 0));

        let unreadable = MemoryVaultStore::new();
        preserve(&unreadable, BUNDLE_ID, b"CANARY-unreadable-ciphertext");
        let mut confirmer = ScriptedConfirmer::accepting();
        assert!(matches!(
            RecoveryPurgeOperations::new(&keys, &unreadable).purge(
                BUNDLE_ID,
                INTERACTION,
                &mut confirmer
            ),
            Err(RecoveryPurgeError::Vault(_))
        ));
        assert_eq!(confirmer.calls, 0);
        assert_eq!(recovery_counts(&unreadable), (1, 0));
    }

    #[test]
    fn keychain_failure_leaves_a_durable_plan_that_retries_without_decryption() {
        let (keys, store, _) = initialized();
        let (old_key_id, envelope) = standalone_envelope(&keys, 3);
        preserve(&store, BUNDLE_ID, &envelope);
        keys.fail_next_delete(KeyProviderErrorKind::BackendFailure);
        let mut confirmer = ScriptedConfirmer::accepting();

        assert!(matches!(
            RecoveryPurgeOperations::new(&keys, &store).purge(
                BUNDLE_ID,
                INTERACTION,
                &mut confirmer
            ),
            Err(RecoveryPurgeError::SecureStore(error))
                if error.kind() == KeyProviderErrorKind::BackendFailure
        ));
        assert!(keys.contains(&old_key_id));
        assert_eq!(recovery_counts(&store), (0, 1));

        store.fail_next_recovery_purge_stage(RecoveryPurgeStageFault::NotCommitted);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert_eq!(
            RecoveryPurgeOperations::new(&keys, &store)
                .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
                .unwrap_err(),
            RecoveryPurgeError::StageOutcomeIndeterminate
        );
        assert!(keys.contains(&old_key_id));

        let mut confirmer = ScriptedConfirmer::accepting();
        RecoveryPurgeOperations::new(&keys, &store)
            .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
            .unwrap();
        assert!(!keys.contains(&old_key_id));
        assert_eq!(recovery_counts(&store), (0, 0));
    }

    #[test]
    fn staging_faults_never_guess_whether_key_deletion_is_safe() {
        for fault in [
            RecoveryPurgeStageFault::NotCommitted,
            RecoveryPurgeStageFault::IndeterminateBeforeCommit,
        ] {
            let (keys, store, _) = initialized();
            let (old_key_id, envelope) = standalone_envelope(&keys, 3);
            preserve(&store, BUNDLE_ID, &envelope);
            store.fail_next_recovery_purge_stage(fault);
            let mut confirmer = ScriptedConfirmer::accepting();
            assert!(
                RecoveryPurgeOperations::new(&keys, &store)
                    .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
                    .is_err()
            );
            assert!(keys.contains(&old_key_id));
            assert_eq!(recovery_counts(&store), (1, 0));
        }

        let (keys, store, _) = initialized();
        let (old_key_id, envelope) = standalone_envelope(&keys, 3);
        preserve(&store, BUNDLE_ID, &envelope);
        store.fail_next_recovery_purge_stage(RecoveryPurgeStageFault::IndeterminateAfterCommit);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert_eq!(
            RecoveryPurgeOperations::new(&keys, &store)
                .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
                .unwrap_err(),
            RecoveryPurgeError::StageOutcomeIndeterminate
        );
        assert!(keys.contains(&old_key_id));
        assert_eq!(recovery_counts(&store), (0, 1));

        let mut confirmer = ScriptedConfirmer::accepting();
        RecoveryPurgeOperations::new(&keys, &store)
            .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
            .unwrap();
        assert!(!keys.contains(&old_key_id));
    }

    #[test]
    fn cleanup_faults_are_resumable_after_the_key_is_gone() {
        for fault in [
            RecoveryPurgeRemovalFault::NotCommitted,
            RecoveryPurgeRemovalFault::IndeterminateBeforeCommit,
        ] {
            let (keys, store, _) = initialized();
            let (old_key_id, envelope) = standalone_envelope(&keys, 3);
            preserve(&store, BUNDLE_ID, &envelope);
            store.fail_next_recovery_purge_removal(fault);
            let mut confirmer = ScriptedConfirmer::accepting();
            assert!(
                RecoveryPurgeOperations::new(&keys, &store)
                    .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
                    .is_err()
            );
            assert!(!keys.contains(&old_key_id));
            assert_eq!(recovery_counts(&store), (0, 1));

            let mut confirmer = ScriptedConfirmer::accepting();
            RecoveryPurgeOperations::new(&keys, &store)
                .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
                .unwrap();
            assert_eq!(recovery_counts(&store), (0, 0));
        }

        let (keys, store, _) = initialized();
        let (_, envelope) = standalone_envelope(&keys, 3);
        preserve(&store, BUNDLE_ID, &envelope);
        store.fail_next_recovery_purge_removal(RecoveryPurgeRemovalFault::IndeterminateAfterCommit);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert!(
            RecoveryPurgeOperations::new(&keys, &store)
                .purge(BUNDLE_ID, INTERACTION, &mut confirmer)
                .is_ok()
        );
        assert_eq!(recovery_counts(&store), (0, 0));
    }
}
