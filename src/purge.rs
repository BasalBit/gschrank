#![forbid(unsafe_code)]

use std::{collections::BTreeSet, error::Error, fmt};

use crate::{
    KeyId,
    confirmation::{ConfirmationError, TypedConfirmationRequest, TypedConfirmer},
    inspect_envelope,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderError, KeyProviderErrorKind},
    open_envelope,
    vault_store::{
        CommitOutcome, FullPurgePending, VaultStore, VaultStoreError, VaultStoreErrorKind,
        VaultTransaction,
    },
};

const PURGE_CONFIRMATION: TypedConfirmationRequest = TypedConfirmationRequest {
    expected: "PURGE",
    action: "permanently purge all local Gschrank vault state",
    warning: "Local encrypted vaults, internal recovery data, configuration, and their authenticated Keychain items will be removed. External backups that use those keys will become unreadable. This does not provide secure erasure.",
};

/// A safe failure supplied while removing persistent shell integration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FullPurgePreparationError {
    exit_code: u8,
}

impl FullPurgePreparationError {
    pub(crate) const fn new(exit_code: u8) -> Self {
        Self { exit_code }
    }

    pub(crate) const fn exit_code(self) -> u8 {
        self.exit_code
    }
}

/// Non-secret completion metadata for a destructive full purge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FullPurgeReceipt {
    pub(crate) retired_key_count: usize,
    pub(crate) unauthenticated_artifact_count: usize,
}

/// Value- and name-free destructive-purge failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FullPurgeError {
    Confirmation(ConfirmationError),
    PreparationFailed(FullPurgePreparationError),
    SecureStore(KeyProviderError),
    Store(VaultStoreError),
    StageNotCommitted,
    StageOutcomeIndeterminate,
    PlanNotCommitted,
    PlanOutcomeIndeterminate,
    CleanupNotCommitted,
    CleanupOutcomeIndeterminate,
}

impl FullPurgeError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::Confirmation(error) => error.exit_code(),
            Self::PreparationFailed(error) => error.exit_code(),
            Self::SecureStore(_) => 11,
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
            Self::StageNotCommitted | Self::PlanNotCommitted | Self::CleanupNotCommitted => 1,
            Self::StageOutcomeIndeterminate
            | Self::PlanOutcomeIndeterminate
            | Self::CleanupOutcomeIndeterminate => 15,
        }
    }
}

impl From<ConfirmationError> for FullPurgeError {
    fn from(error: ConfirmationError) -> Self {
        Self::Confirmation(error)
    }
}

impl From<VaultStoreError> for FullPurgeError {
    fn from(error: VaultStoreError) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for FullPurgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Confirmation(error) => error.fmt(formatter),
            Self::PreparationFailed(_) => formatter.write_str(
                "persistent shell integration could not be removed; destructive purge did not continue",
            ),
            Self::SecureStore(_) => formatter.write_str(
                "secure-store access failed; staged purge state was retained for retry",
            ),
            Self::Store(_) => formatter.write_str("the local full-purge store failed"),
            Self::StageNotCommitted => formatter
                .write_str("local vault state was not staged; no Keychain item was deleted"),
            Self::StageOutcomeIndeterminate => formatter.write_str(
                "full-purge staging is indeterminate; no Keychain deletion was attempted",
            ),
            Self::PlanNotCommitted => formatter.write_str(
                "the authenticated Keychain deletion plan was not committed; no key was deleted",
            ),
            Self::PlanOutcomeIndeterminate => formatter.write_str(
                "the Keychain deletion plan is indeterminate; no key was deleted",
            ),
            Self::CleanupNotCommitted => formatter.write_str(
                "Keychain deletion completed but staged local purge data remains",
            ),
            Self::CleanupOutcomeIndeterminate => formatter.write_str(
                "full-purge cleanup is indeterminate; inspect diagnostics before retrying",
            ),
        }
    }
}

impl Error for FullPurgeError {}

/// Destructive, staged, retryable removal of all locally discoverable state.
pub(crate) struct FullPurgeOperations<'dependencies, K, S> {
    keys: &'dependencies K,
    store: &'dependencies S,
}

impl<'dependencies, K, S> FullPurgeOperations<'dependencies, K, S>
where
    K: KeyProvider,
    S: VaultStore,
{
    pub(crate) const fn new(keys: &'dependencies K, store: &'dependencies S) -> Self {
        Self { keys, store }
    }

    pub(crate) fn purge<F>(
        &self,
        interaction: InteractionPolicy,
        confirmer: &mut dyn TypedConfirmer,
        prepare: F,
    ) -> Result<FullPurgeReceipt, FullPurgeError>
    where
        F: FnOnce() -> Result<(), FullPurgePreparationError>,
    {
        self.store.initialization_transaction(|transaction| {
            confirmer.confirm(PURGE_CONFIRMATION)?;
            prepare().map_err(FullPurgeError::PreparationFailed)?;

            Self::stage_and_verify(transaction)?;
            let pending = transaction
                .read_full_purge_pending()?
                .ok_or(FullPurgeError::StageOutcomeIndeterminate)?;
            let (key_ids, unauthenticated_artifact_count) =
                if let Some(key_ids) = pending.key_ids.as_ref() {
                    (key_ids.clone(), 0)
                } else {
                    let (key_ids, skipped) = self.collect_key_ids(&pending, interaction)?;
                    Self::write_plan_and_verify(transaction, &key_ids)?;
                    (key_ids, skipped)
                };

            let mut retired_key_count = 0;
            for key_id in &key_ids {
                match self.keys.delete(key_id, interaction) {
                    Ok(()) => retired_key_count += 1,
                    Err(error) if error.kind() == KeyProviderErrorKind::NotFound => {
                        retired_key_count += 1;
                    }
                    Err(error) => return Err(FullPurgeError::SecureStore(error)),
                }
            }

            Self::remove_staged_and_verify(transaction)?;
            Ok(FullPurgeReceipt {
                retired_key_count,
                unauthenticated_artifact_count,
            })
        })
    }

    fn collect_key_ids(
        &self,
        pending: &FullPurgePending,
        interaction: InteractionPolicy,
    ) -> Result<(Vec<KeyId>, usize), FullPurgeError> {
        let mut key_ids = pending
            .trusted_key_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut unauthenticated_artifact_count = 0;
        for envelope in &pending.envelopes {
            let Ok(metadata) = inspect_envelope(envelope) else {
                unauthenticated_artifact_count += 1;
                continue;
            };
            if key_ids.contains(&metadata.key_id) {
                continue;
            }
            let key = match self.keys.load(&metadata.key_id, interaction) {
                Ok(key) => key,
                Err(error)
                    if matches!(
                        error.kind(),
                        KeyProviderErrorKind::NotFound | KeyProviderErrorKind::InvalidKeyMaterial
                    ) =>
                {
                    unauthenticated_artifact_count += 1;
                    continue;
                }
                Err(error) => return Err(FullPurgeError::SecureStore(error)),
            };
            match open_envelope(envelope, &key) {
                Ok(opened)
                    if opened.key_id == metadata.key_id && opened.vault_id == metadata.vault_id =>
                {
                    key_ids.insert(metadata.key_id);
                }
                Ok(_) | Err(_) => unauthenticated_artifact_count += 1,
            }
        }
        Ok((
            key_ids.into_iter().collect(),
            unauthenticated_artifact_count,
        ))
    }

    fn stage_and_verify(transaction: &mut dyn VaultTransaction) -> Result<(), FullPurgeError> {
        let outcome = transaction.stage_full_purge()?;
        let pending = transaction.read_full_purge_pending()?.is_some();
        if outcome == CommitOutcome::Committed && pending {
            return Ok(());
        }
        Err(match outcome {
            CommitOutcome::NotCommitted if !pending => FullPurgeError::StageNotCommitted,
            CommitOutcome::NotCommitted
            | CommitOutcome::Committed
            | CommitOutcome::Indeterminate => FullPurgeError::StageOutcomeIndeterminate,
        })
    }

    fn write_plan_and_verify(
        transaction: &mut dyn VaultTransaction,
        key_ids: &[KeyId],
    ) -> Result<(), FullPurgeError> {
        let outcome = transaction.write_full_purge_plan(key_ids)?;
        let exact = transaction
            .read_full_purge_pending()?
            .is_some_and(|pending| pending.key_ids.as_deref() == Some(key_ids));
        if outcome == CommitOutcome::Committed && exact {
            return Ok(());
        }
        Err(match outcome {
            CommitOutcome::NotCommitted if !exact => FullPurgeError::PlanNotCommitted,
            CommitOutcome::NotCommitted
            | CommitOutcome::Committed
            | CommitOutcome::Indeterminate => FullPurgeError::PlanOutcomeIndeterminate,
        })
    }

    fn remove_staged_and_verify(
        transaction: &mut dyn VaultTransaction,
    ) -> Result<(), FullPurgeError> {
        let outcome = transaction.remove_full_purge_pending()?;
        let absent = transaction.read_full_purge_pending()?.is_none();
        if absent {
            return Ok(());
        }
        Err(match outcome {
            CommitOutcome::NotCommitted => FullPurgeError::CleanupNotCommitted,
            CommitOutcome::Committed | CommitOutcome::Indeterminate => {
                FullPurgeError::CleanupOutcomeIndeterminate
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use std::{
        fs::{self, DirBuilder},
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::{
        EnvironmentName, MasterKey, ProfileName, SecretValue, Vault, VaultId,
        confirmation::TypedConfirmationRequest,
        init::Initializer,
        seal_vault,
        testing::{FullPurgeFault, MemoryKeyProvider, MemoryVaultStore},
        vault_store::{
            RecoveryArtifacts, RecoveryBundleId, RecoveryBundleMetadata, RecoveryReason, VaultStore,
        },
    };

    const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;
    const BUNDLE_ID: RecoveryBundleId = RecoveryBundleId::from_bytes([7; 16]);
    const OTHER_BUNDLE_ID: RecoveryBundleId = RecoveryBundleId::from_bytes([8; 16]);

    #[cfg(target_os = "macos")]
    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[cfg(target_os = "macos")]
    struct TestDirectory(PathBuf);

    #[cfg(target_os = "macos")]
    impl TestDirectory {
        fn new() -> Self {
            let id = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "gschrank-full-purge-test-{}-{id}",
                std::process::id()
            ));
            let mut builder = DirBuilder::new();
            builder.mode(0o700).create(&root).unwrap();
            Self(root)
        }

        fn data(&self) -> PathBuf {
            self.0.join("data")
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

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
            assert!(request.warning.contains("External backups"));
            assert!(request.warning.contains("secure erasure"));
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
        let key_id = inspect_envelope(&store.live().unwrap()).unwrap().key_id;
        (keys, store, key_id)
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
                SecretValue::from_string("CANARY-full-purge-secret".to_owned()).unwrap(),
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
                        created_at_unix_seconds: 1,
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

    fn full_pending(store: &MemoryVaultStore) -> Option<FullPurgePending> {
        store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_full_purge_pending())
            .unwrap()
    }

    #[test]
    fn purges_all_authenticated_internal_keys_but_keeps_unreferenced_keychain_items() {
        let (keys, store, live_key_id) = initialized();
        let (recovery_key_id, recovery) = standalone_envelope(&keys, 3);
        preserve(&store, BUNDLE_ID, &recovery);
        let (pending_key_id, pending) = standalone_envelope(&keys, 5);
        preserve(&store, OTHER_BUNDLE_ID, &pending);
        store
            .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                transaction.stage_recovery_purge(OTHER_BUNDLE_ID, &[pending_key_id])?;
                Ok(())
            })
            .unwrap();
        let external_key_id = KeyId::from_bytes([9; 16]);
        keys.insert(external_key_id, &MasterKey::from_bytes([10; 32]));
        let mut confirmer = ScriptedConfirmer::accepting();
        let mut prepared = false;

        let receipt = FullPurgeOperations::new(&keys, &store)
            .purge(INTERACTION, &mut confirmer, || {
                prepared = true;
                Ok(())
            })
            .unwrap();

        assert!(prepared);
        assert_eq!(confirmer.calls, 1);
        assert_eq!(receipt.retired_key_count, 3);
        assert_eq!(receipt.unauthenticated_artifact_count, 0);
        assert!(!keys.contains(&live_key_id));
        assert!(!keys.contains(&recovery_key_id));
        assert!(!keys.contains(&pending_key_id));
        assert!(keys.contains(&external_key_id));
        assert!(full_pending(&store).is_none());
        assert!(store.live().is_none());
    }

    #[test]
    fn rejection_and_preparation_failure_do_not_stage_or_delete() {
        let (keys, store, live_key_id) = initialized();
        let mut rejected = ScriptedConfirmer {
            result: Err(ConfirmationError::Rejected),
            calls: 0,
        };
        let mut prepared = false;
        assert_eq!(
            FullPurgeOperations::new(&keys, &store)
                .purge(INTERACTION, &mut rejected, || {
                    prepared = true;
                    Ok(())
                })
                .unwrap_err(),
            FullPurgeError::Confirmation(ConfirmationError::Rejected)
        );
        assert!(!prepared);
        assert!(keys.contains(&live_key_id));
        assert!(store.live().is_some());

        let mut confirmer = ScriptedConfirmer::accepting();
        assert_eq!(
            FullPurgeOperations::new(&keys, &store)
                .purge(INTERACTION, &mut confirmer, || {
                    Err(FullPurgePreparationError::new(13))
                })
                .unwrap_err(),
            FullPurgeError::PreparationFailed(FullPurgePreparationError::new(13))
        );
        assert!(full_pending(&store).is_none());
        assert!(keys.contains(&live_key_id));
    }

    #[test]
    fn keychain_access_failure_leaves_a_global_freeze_that_retries_safely() {
        let (keys, store, live_key_id) = initialized();
        keys.fail_next_load(KeyProviderErrorKind::BackendFailure);
        let mut confirmer = ScriptedConfirmer::accepting();

        assert!(matches!(
            FullPurgeOperations::new(&keys, &store).purge(
                INTERACTION,
                &mut confirmer,
                || Ok(())
            ),
            Err(FullPurgeError::SecureStore(error))
                if error.kind() == KeyProviderErrorKind::BackendFailure
        ));
        let pending = full_pending(&store).unwrap();
        assert!(pending.key_ids.is_none());
        assert!(keys.contains(&live_key_id));
        assert!(store.live().is_none());

        let mut confirmer = ScriptedConfirmer::accepting();
        FullPurgeOperations::new(&keys, &store)
            .purge(INTERACTION, &mut confirmer, || Ok(()))
            .unwrap();
        assert!(!keys.contains(&live_key_id));
        assert!(full_pending(&store).is_none());
    }

    #[test]
    fn unauthenticated_artifacts_are_removed_without_deleting_their_claimed_key() {
        let (keys, store, live_key_id) = initialized();
        let (claimed_key_id, mut envelope) = standalone_envelope(&keys, 3);
        let last = envelope.len() - 1;
        envelope[last] ^= 1;
        preserve(&store, BUNDLE_ID, &envelope);
        let mut confirmer = ScriptedConfirmer::accepting();

        let receipt = FullPurgeOperations::new(&keys, &store)
            .purge(INTERACTION, &mut confirmer, || Ok(()))
            .unwrap();

        assert_eq!(receipt.retired_key_count, 1);
        assert_eq!(receipt.unauthenticated_artifact_count, 1);
        assert!(!keys.contains(&live_key_id));
        assert!(keys.contains(&claimed_key_id));
        assert!(full_pending(&store).is_none());
    }

    #[test]
    fn indeterminate_stage_and_plan_never_authorize_key_deletion() {
        for (fault, expected) in [
            (
                FullPurgeFault::NotCommitted,
                FullPurgeError::StageNotCommitted,
            ),
            (
                FullPurgeFault::IndeterminateBeforeCommit,
                FullPurgeError::StageOutcomeIndeterminate,
            ),
        ] {
            let (keys, store, live_key_id) = initialized();
            store.fail_next_full_purge_stage(fault);
            let mut confirmer = ScriptedConfirmer::accepting();
            assert_eq!(
                FullPurgeOperations::new(&keys, &store)
                    .purge(INTERACTION, &mut confirmer, || Ok(()))
                    .unwrap_err(),
                expected
            );
            assert!(keys.contains(&live_key_id));
        }

        let (keys, store, live_key_id) = initialized();
        store.fail_next_full_purge_stage(FullPurgeFault::IndeterminateAfterCommit);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert_eq!(
            FullPurgeOperations::new(&keys, &store)
                .purge(INTERACTION, &mut confirmer, || Ok(()))
                .unwrap_err(),
            FullPurgeError::StageOutcomeIndeterminate
        );
        assert!(keys.contains(&live_key_id));

        store.fail_next_full_purge_plan(FullPurgeFault::IndeterminateAfterCommit);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert_eq!(
            FullPurgeOperations::new(&keys, &store)
                .purge(INTERACTION, &mut confirmer, || Ok(()))
                .unwrap_err(),
            FullPurgeError::PlanOutcomeIndeterminate
        );
        assert!(keys.contains(&live_key_id));
        assert_eq!(
            full_pending(&store).unwrap().key_ids,
            Some(vec![live_key_id])
        );

        let mut confirmer = ScriptedConfirmer::accepting();
        FullPurgeOperations::new(&keys, &store)
            .purge(INTERACTION, &mut confirmer, || Ok(()))
            .unwrap();
        assert!(!keys.contains(&live_key_id));
    }

    #[test]
    fn deletion_and_cleanup_failures_resume_after_already_deleted_keys() {
        let (keys, store, live_key_id) = initialized();
        keys.fail_next_delete(KeyProviderErrorKind::BackendFailure);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert!(matches!(
            FullPurgeOperations::new(&keys, &store).purge(INTERACTION, &mut confirmer, || Ok(())),
            Err(FullPurgeError::SecureStore(_))
        ));
        assert!(keys.contains(&live_key_id));
        assert_eq!(
            full_pending(&store).unwrap().key_ids,
            Some(vec![live_key_id])
        );

        store.fail_next_full_purge_removal(FullPurgeFault::NotCommitted);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert_eq!(
            FullPurgeOperations::new(&keys, &store)
                .purge(INTERACTION, &mut confirmer, || Ok(()))
                .unwrap_err(),
            FullPurgeError::CleanupNotCommitted
        );
        assert!(!keys.contains(&live_key_id));
        assert!(full_pending(&store).is_some());

        let mut confirmer = ScriptedConfirmer::accepting();
        FullPurgeOperations::new(&keys, &store)
            .purge(INTERACTION, &mut confirmer, || Ok(()))
            .unwrap();
        assert!(full_pending(&store).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_local_store_full_purge_can_be_followed_by_fresh_initialization() {
        use crate::platform::macos::LocalVaultStore;

        let test = TestDirectory::new();
        let keys = MemoryKeyProvider::new();
        let store = LocalVaultStore::new(test.data());
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let old_key_id = store
            .shared_read::<_, VaultStoreError, _>(|read| {
                let live = read.read_live()?.unwrap();
                Ok(inspect_envelope(&live).unwrap().key_id)
            })
            .unwrap();
        let mut confirmer = ScriptedConfirmer::accepting();

        FullPurgeOperations::new(&keys, &store)
            .purge(INTERACTION, &mut confirmer, || Ok(()))
            .unwrap();

        assert!(!keys.contains(&old_key_id));
        assert!(
            store
                .shared_read::<_, VaultStoreError, _>(|read| {
                    Ok(read.read_full_purge_pending()?.is_none() && read.read_live()?.is_none())
                })
                .unwrap()
        );
        let recreated = Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        assert!(matches!(
            recreated,
            crate::init::InitOutcome::Created { .. }
        ));
    }
}
