#![forbid(unsafe_code)]

use std::{error::Error, fmt, time::SystemTime};

use crate::{
    EnvelopeError, KeyId, MasterKey, Vault, VaultId,
    codec::encode_payload,
    confirmation::{ConfirmationError, TypedConfirmationRequest, TypedConfirmer},
    inspect_envelope,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderError, KeyProviderErrorKind},
    open_envelope, seal_vault,
    vault_store::{
        CommitOutcome, RecoveryArtifacts, RecoveryBundleId, RecoveryBundleMetadata, RecoveryReason,
        VaultStore, VaultStoreError, VaultStoreErrorKind, VaultTransaction,
    },
};

const MAX_ID_COLLISION_RETRIES: usize = 8;
const MAX_RECOVERY_ID_ATTEMPTS: usize = 8;
const REBUILD_CONFIRMATION: TypedConfirmationRequest = TypedConfirmationRequest {
    expected: "REBUILD",
    action: "rebuild the vault with a new identity and master key",
    warning: "Every profile and value will be copied into a newly keyed vault. The exact current encrypted vault and its Keychain item will be retained for recovery.",
};

/// Safe metadata for a completed fresh-vault rebuild.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RebuildReceipt {
    pub(crate) vault_id: VaultId,
    pub(crate) key_id: KeyId,
    pub(crate) recovery_bundle: RecoveryBundleId,
}

/// Value- and name-free fresh-vault rebuild failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RebuildError {
    NotInitialized,
    ConflictingInitialization,
    Confirmation(ConfirmationError),
    SecureStore(KeyProviderError),
    VaultKeyMissing,
    InvalidKeyMaterial,
    Vault(EnvelopeError),
    Store(VaultStoreError),
    CandidateMismatch,
    RecoveryNotCommitted,
    RecoveryOutcomeIndeterminate,
    CommitNotCompleted,
    CommitOutcomeIndeterminate,
}

impl RebuildError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::NotInitialized => 10,
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
            Self::ConflictingInitialization | Self::CandidateMismatch => 14,
            Self::RecoveryNotCommitted | Self::CommitNotCompleted => 1,
            Self::RecoveryOutcomeIndeterminate | Self::CommitOutcomeIndeterminate => 15,
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

impl From<ConfirmationError> for RebuildError {
    fn from(error: ConfirmationError) -> Self {
        Self::Confirmation(error)
    }
}

impl From<EnvelopeError> for RebuildError {
    fn from(error: EnvelopeError) -> Self {
        Self::Vault(error)
    }
}

impl From<VaultStoreError> for RebuildError {
    fn from(error: VaultStoreError) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for RebuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotInitialized => "Gschrank is not initialized",
            Self::ConflictingInitialization => {
                "a reserved initialization candidate must be resolved before rebuild"
            }
            Self::Confirmation(error) => return error.fmt(formatter),
            Self::SecureStore(_) => "secure-store access failed",
            Self::VaultKeyMissing => "the vault's secure-store key is missing",
            Self::InvalidKeyMaterial => "the vault's secure-store key is invalid",
            Self::Vault(_) => "the encrypted vault is unreadable",
            Self::Store(_) => "the local vault or recovery store failed",
            Self::CandidateMismatch => {
                "the reserved rebuild candidate does not match the current logical vault"
            }
            Self::RecoveryNotCommitted => {
                "the current encrypted vault could not be preserved; rebuild did not continue"
            }
            Self::RecoveryOutcomeIndeterminate => {
                "rebuild recovery preservation is indeterminate; the live vault was not replaced"
            }
            Self::CommitNotCompleted => {
                "the rebuilt vault did not replace the live vault; retry rebuild to resume"
            }
            Self::CommitOutcomeIndeterminate => {
                "vault rebuild is indeterminate; inspect status before retrying"
            }
        })
    }
}

impl Error for RebuildError {}

enum PendingCandidate {
    Absent,
    KeyMissing,
    Ready {
        envelope: zeroize::Zeroizing<Vec<u8>>,
        key: MasterKey,
        vault_id: VaultId,
        key_id: KeyId,
    },
}

/// Fresh-identity rebuild policy over portable key and storage seams.
pub(crate) struct RebuildOperations<'dependencies, K, S> {
    keys: &'dependencies K,
    store: &'dependencies S,
}

impl<'dependencies, K, S> RebuildOperations<'dependencies, K, S>
where
    K: KeyProvider,
    S: VaultStore,
{
    pub(crate) const fn new(keys: &'dependencies K, store: &'dependencies S) -> Self {
        Self { keys, store }
    }

    pub(crate) fn rebuild(
        &self,
        interaction: InteractionPolicy,
        confirmer: &mut dyn TypedConfirmer,
    ) -> Result<RebuildReceipt, RebuildError> {
        self.store.exclusive_transaction(|transaction| {
            if transaction.read_init_pending()?.is_some() {
                return Err(RebuildError::ConflictingInitialization);
            }
            let live = transaction
                .read_live()?
                .ok_or(RebuildError::NotInitialized)?;
            let live_metadata = inspect_envelope(&live)?;
            let old_key = self
                .keys
                .load(&live_metadata.key_id, interaction)
                .map_err(RebuildError::from_key_provider)?;
            let mut opened = open_envelope(&live, &old_key)?;
            opened.vault.begin_fresh_identity();
            let pending = self.inspect_pending(transaction, &opened.vault, interaction)?;

            confirmer.confirm(REBUILD_CONFIRMATION)?;
            let recovery_bundle = Self::preserve_live(transaction, &live)?;
            match pending {
                PendingCandidate::Absent => {
                    self.create_candidate(transaction, &opened.vault, recovery_bundle, interaction)
                }
                PendingCandidate::KeyMissing => {
                    transaction.discard_rebuild_pending()?;
                    self.create_candidate(transaction, &opened.vault, recovery_bundle, interaction)
                }
                PendingCandidate::Ready {
                    envelope,
                    key,
                    vault_id,
                    key_id,
                } => Self::promote_and_verify(
                    transaction,
                    &envelope,
                    &key,
                    vault_id,
                    key_id,
                    &opened.vault,
                    recovery_bundle,
                ),
            }
        })
    }

    fn inspect_pending(
        &self,
        transaction: &mut dyn VaultTransaction,
        expected: &Vault,
        interaction: InteractionPolicy,
    ) -> Result<PendingCandidate, RebuildError> {
        let Some(envelope) = transaction.read_rebuild_pending()? else {
            return Ok(PendingCandidate::Absent);
        };
        let metadata = inspect_envelope(&envelope)?;
        let key = match self.keys.load(&metadata.key_id, interaction) {
            Ok(key) => key,
            Err(error) if error.kind() == KeyProviderErrorKind::NotFound => {
                return Ok(PendingCandidate::KeyMissing);
            }
            Err(error) => return Err(RebuildError::from_key_provider(error)),
        };
        let opened = open_envelope(&envelope, &key)?;
        if !same_logical_vault(expected, &opened.vault)? {
            return Err(RebuildError::CandidateMismatch);
        }
        Ok(PendingCandidate::Ready {
            envelope,
            key,
            vault_id: opened.vault_id,
            key_id: opened.key_id,
        })
    }

    fn create_candidate(
        &self,
        transaction: &mut dyn VaultTransaction,
        vault: &Vault,
        recovery_bundle: RecoveryBundleId,
        interaction: InteractionPolicy,
    ) -> Result<RebuildReceipt, RebuildError> {
        for _ in 0..MAX_ID_COLLISION_RETRIES {
            let vault_id = VaultId::generate()?;
            let key_id = KeyId::generate()?;
            let key = MasterKey::generate()?;
            let envelope = seal_vault(vault, vault_id, key_id, &key)?;
            transaction.create_rebuild_pending(&envelope)?;
            match self.keys.store_new(&key_id, &key, interaction) {
                Ok(()) => {
                    let committed = transaction
                        .read_rebuild_pending()?
                        .ok_or(RebuildError::CommitOutcomeIndeterminate)?;
                    if committed.as_slice() != envelope.as_slice()
                        || open_envelope(&committed, &key).is_err()
                    {
                        return Err(RebuildError::CommitOutcomeIndeterminate);
                    }
                    return Self::promote_and_verify(
                        transaction,
                        &envelope,
                        &key,
                        vault_id,
                        key_id,
                        vault,
                        recovery_bundle,
                    );
                }
                Err(error) if error.kind() == KeyProviderErrorKind::AlreadyExists => {
                    transaction.discard_rebuild_pending()?;
                }
                Err(error) => {
                    if error.definitely_did_not_store() {
                        transaction.discard_rebuild_pending()?;
                    }
                    return Err(RebuildError::from_key_provider(error));
                }
            }
        }
        Err(RebuildError::SecureStore(KeyProviderError::new(
            KeyProviderErrorKind::AlreadyExists,
        )))
    }

    fn preserve_live(
        transaction: &mut dyn VaultTransaction,
        live: &[u8],
    ) -> Result<RecoveryBundleId, RebuildError> {
        if let Some(existing) = transaction
            .read_recovery_bundles()?
            .into_iter()
            .find(|bundle| {
                bundle.metadata.reason == RecoveryReason::Rebuild
                    && bundle
                        .live
                        .as_ref()
                        .is_some_and(|bytes| bytes.as_slice() == live)
                    && bundle.init_pending.is_none()
                    && bundle.rebuild_pending.is_none()
            })
        {
            return Ok(existing.metadata.id);
        }

        let created_at_unix_seconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::IoFailure))?
            .as_secs();
        for _ in 0..MAX_RECOVERY_ID_ATTEMPTS {
            let metadata = RecoveryBundleMetadata {
                id: RecoveryBundleId::generate()?,
                created_at_unix_seconds,
                reason: RecoveryReason::Rebuild,
            };
            let outcome = match transaction.preserve_recovery(
                metadata,
                RecoveryArtifacts {
                    live: Some(live),
                    init_pending: None,
                    rebuild_pending: None,
                },
            ) {
                Err(error) if error.kind() == VaultStoreErrorKind::Conflict => continue,
                result => result?,
            };
            let exact_copy = transaction
                .read_recovery_bundles()?
                .into_iter()
                .find(|bundle| bundle.metadata == metadata)
                .is_some_and(|bundle| {
                    bundle
                        .live
                        .as_ref()
                        .is_some_and(|bytes| bytes.as_slice() == live)
                        && bundle.init_pending.is_none()
                        && bundle.rebuild_pending.is_none()
                });
            if exact_copy {
                return Ok(metadata.id);
            }
            return Err(match outcome {
                CommitOutcome::NotCommitted => RebuildError::RecoveryNotCommitted,
                CommitOutcome::Committed | CommitOutcome::Indeterminate => {
                    RebuildError::RecoveryOutcomeIndeterminate
                }
            });
        }
        Err(VaultStoreError::new(VaultStoreErrorKind::Conflict).into())
    }

    #[allow(clippy::too_many_arguments)]
    fn promote_and_verify(
        transaction: &mut dyn VaultTransaction,
        expected_envelope: &[u8],
        key: &MasterKey,
        expected_vault_id: VaultId,
        expected_key_id: KeyId,
        expected_vault: &Vault,
        recovery_bundle: RecoveryBundleId,
    ) -> Result<RebuildReceipt, RebuildError> {
        let outcome = transaction.promote_rebuild_pending()?;
        let committed = transaction.read_live()?;
        let exact_commit = committed.as_ref().is_some_and(|envelope| {
            if envelope.as_slice() != expected_envelope {
                return false;
            }
            open_envelope(envelope, key).is_ok_and(|opened| {
                opened.vault_id == expected_vault_id
                    && opened.key_id == expected_key_id
                    && same_logical_vault(expected_vault, &opened.vault).unwrap_or(false)
            })
        }) && transaction.read_rebuild_pending()?.is_none();

        if exact_commit {
            return Ok(RebuildReceipt {
                vault_id: expected_vault_id,
                key_id: expected_key_id,
                recovery_bundle,
            });
        }
        Err(match outcome {
            CommitOutcome::NotCommitted => RebuildError::CommitNotCompleted,
            CommitOutcome::Committed | CommitOutcome::Indeterminate => {
                RebuildError::CommitOutcomeIndeterminate
            }
        })
    }
}

fn same_logical_vault(expected: &Vault, actual: &Vault) -> Result<bool, RebuildError> {
    let expected = encode_payload(expected).map_err(EnvelopeError::from)?;
    let actual = encode_payload(actual).map_err(EnvelopeError::from)?;
    Ok(expected.as_slice() == actual.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EnvironmentName, ProfileName, SecretValue,
        confirmation::TypedConfirmationRequest,
        init::Initializer,
        profiles::ProfileOperations,
        testing::{
            MemoryKeyProvider, MemoryVaultStore, RebuildPromotionFault, RecoveryPreservationFault,
        },
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
    }

    impl TypedConfirmer for ScriptedConfirmer {
        fn confirm(&mut self, request: TypedConfirmationRequest) -> Result<(), ConfirmationError> {
            self.calls += 1;
            assert_eq!(request.expected, "REBUILD");
            assert!(!request.warning.contains("CANARY"));
            self.result
        }
    }

    fn initialized_with_secret() -> (MemoryKeyProvider, MemoryVaultStore, KeyId, Vec<u8>) {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let profile = ProfileName::new("work").unwrap();
        let profiles = ProfileOperations::new(&keys, &store);
        profiles.create(profile.clone(), INTERACTION).unwrap();
        profiles
            .set(
                &profile,
                EnvironmentName::new("TOKEN").unwrap(),
                SecretValue::from_string("CANARY-rebuild-secret".to_owned()).unwrap(),
                INTERACTION,
            )
            .unwrap();
        let live = store.live().unwrap();
        let key_id = inspect_envelope(&live).unwrap().key_id;
        (keys, store, key_id, live)
    }

    #[test]
    fn rebuild_copies_every_value_at_revision_zero_under_an_independent_key() {
        let (keys, store, old_key_id, old_live) = initialized_with_secret();
        let mut confirmer = ScriptedConfirmer::accepting();

        let receipt = RebuildOperations::new(&keys, &store)
            .rebuild(INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(confirmer.calls, 1);
        assert_ne!(receipt.key_id, old_key_id);
        assert!(keys.contains(&old_key_id));
        assert!(keys.contains(&receipt.key_id));
        assert_eq!(keys.key_count(), 2);
        assert!(store.rebuild_pending().is_none());
        let new_key = keys.load(&receipt.key_id, INTERACTION).unwrap();
        let opened = open_envelope(&store.live().unwrap(), &new_key).unwrap();
        assert_eq!(opened.vault.revision(), 0);
        assert_eq!(opened.vault.profile_names().len(), 1);
        assert_eq!(
            opened.vault.secret(
                &ProfileName::new("work").unwrap(),
                &EnvironmentName::new("TOKEN").unwrap(),
            ),
            Some(&b"CANARY-rebuild-secret"[..])
        );
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].metadata.id, receipt.recovery_bundle);
        assert_eq!(bundles[0].metadata.reason, RecoveryReason::Rebuild);
        assert_eq!(
            bundles[0].live.as_ref().map(|bytes| bytes.as_slice()),
            Some(old_live.as_slice())
        );
    }

    #[test]
    fn rejected_confirmation_and_unhealthy_live_do_not_mutate_state() {
        let (keys, store, _, old_live) = initialized_with_secret();
        let mut confirmer = ScriptedConfirmer {
            result: Err(ConfirmationError::Rejected),
            calls: 0,
        };
        assert_eq!(
            RebuildOperations::new(&keys, &store)
                .rebuild(INTERACTION, &mut confirmer)
                .unwrap_err(),
            RebuildError::Confirmation(ConfirmationError::Rejected)
        );
        assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
        assert_eq!(keys.key_count(), 1);

        store.set_live(b"CANARY-unreadable".to_vec());
        let mut confirmer = ScriptedConfirmer::accepting();
        assert!(matches!(
            RebuildOperations::new(&keys, &store).rebuild(INTERACTION, &mut confirmer),
            Err(RebuildError::Vault(_))
        ));
        assert_eq!(confirmer.calls, 0);
    }

    #[test]
    fn interrupted_promotion_resumes_the_exact_candidate_without_duplicate_recovery() {
        let (keys, store, _, old_live) = initialized_with_secret();
        store.fail_next_rebuild_promotion(RebuildPromotionFault::NotCommitted);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert_eq!(
            RebuildOperations::new(&keys, &store)
                .rebuild(INTERACTION, &mut confirmer)
                .unwrap_err(),
            RebuildError::CommitNotCompleted
        );
        let candidate = store.rebuild_pending().unwrap();
        assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
        assert_eq!(keys.key_count(), 2);
        let mutation_error = ProfileOperations::new(&keys, &store)
            .create(ProfileName::new("blocked").unwrap(), INTERACTION)
            .unwrap_err();
        assert!(matches!(
            mutation_error,
            crate::profiles::ProfileOperationError::Store(error)
                if error.kind() == VaultStoreErrorKind::Conflict
        ));
        assert_eq!(
            store.rebuild_pending().as_deref(),
            Some(candidate.as_slice())
        );

        let mut confirmer = ScriptedConfirmer::accepting();
        RebuildOperations::new(&keys, &store)
            .rebuild(INTERACTION, &mut confirmer)
            .unwrap();
        assert_eq!(store.live().as_deref(), Some(candidate.as_slice()));
        assert!(store.rebuild_pending().is_none());
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(bundles.len(), 1);
    }

    #[test]
    fn indeterminate_after_promotion_is_verified_as_success() {
        let (keys, store, _, _) = initialized_with_secret();
        store.fail_next_rebuild_promotion(RebuildPromotionFault::IndeterminateAfterCommit);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert!(
            RebuildOperations::new(&keys, &store)
                .rebuild(INTERACTION, &mut confirmer)
                .is_ok()
        );
        assert!(store.rebuild_pending().is_none());
    }

    #[test]
    fn indeterminate_before_promotion_keeps_both_authoritative_live_and_candidate() {
        let (keys, store, _, old_live) = initialized_with_secret();
        store.fail_next_rebuild_promotion(RebuildPromotionFault::IndeterminateBeforeCommit);
        let mut confirmer = ScriptedConfirmer::accepting();
        assert_eq!(
            RebuildOperations::new(&keys, &store)
                .rebuild(INTERACTION, &mut confirmer)
                .unwrap_err(),
            RebuildError::CommitOutcomeIndeterminate
        );
        assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
        let candidate = store.rebuild_pending().unwrap();

        let mut confirmer = ScriptedConfirmer::accepting();
        RebuildOperations::new(&keys, &store)
            .rebuild(INTERACTION, &mut confirmer)
            .unwrap();
        assert_eq!(store.live().as_deref(), Some(candidate.as_slice()));
        assert!(store.rebuild_pending().is_none());
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(bundles.len(), 1);
    }

    #[test]
    fn definitively_missing_candidate_key_is_replaced_only_after_confirmation() {
        let (keys, store, _, _) = initialized_with_secret();
        let candidate_key = MasterKey::from_bytes([9; 32]);
        let mut vault = Vault::empty();
        vault
            .create_profile(ProfileName::new("other").unwrap())
            .unwrap();
        let candidate = seal_vault(
            &vault,
            VaultId::from_bytes([7; 16]),
            KeyId::from_bytes([8; 16]),
            &candidate_key,
        )
        .unwrap();
        store.set_rebuild_pending(candidate.to_vec());
        let mut confirmer = ScriptedConfirmer {
            result: Err(ConfirmationError::Rejected),
            calls: 0,
        };
        assert!(
            RebuildOperations::new(&keys, &store)
                .rebuild(INTERACTION, &mut confirmer)
                .is_err()
        );
        assert_eq!(
            store.rebuild_pending().as_deref(),
            Some(candidate.as_slice())
        );

        let mut confirmer = ScriptedConfirmer::accepting();
        assert!(
            RebuildOperations::new(&keys, &store)
                .rebuild(INTERACTION, &mut confirmer)
                .is_ok()
        );
    }

    #[test]
    fn authenticated_mismatched_candidate_freezes_without_confirmation_or_mutation() {
        let (keys, store, _, old_live) = initialized_with_secret();
        let candidate_key_id = KeyId::from_bytes([8; 16]);
        let candidate_key = MasterKey::from_bytes([9; 32]);
        let candidate = seal_vault(
            &Vault::empty(),
            VaultId::from_bytes([7; 16]),
            candidate_key_id,
            &candidate_key,
        )
        .unwrap();
        keys.insert(candidate_key_id, &candidate_key);
        store.set_rebuild_pending(candidate.to_vec());
        let mut confirmer = ScriptedConfirmer::accepting();

        assert_eq!(
            RebuildOperations::new(&keys, &store)
                .rebuild(INTERACTION, &mut confirmer)
                .unwrap_err(),
            RebuildError::CandidateMismatch
        );
        assert_eq!(confirmer.calls, 0);
        assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
        assert_eq!(
            store.rebuild_pending().as_deref(),
            Some(candidate.as_slice())
        );
    }

    #[test]
    fn ambiguous_key_store_failure_retains_the_candidate_for_safe_retry() {
        let (keys, store, _, old_live) = initialized_with_secret();
        keys.fail_next_store(KeyProviderErrorKind::BackendFailure);
        let mut confirmer = ScriptedConfirmer::accepting();

        assert!(matches!(
            RebuildOperations::new(&keys, &store).rebuild(INTERACTION, &mut confirmer),
            Err(RebuildError::SecureStore(error))
                if error.kind() == KeyProviderErrorKind::BackendFailure
        ));
        assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
        assert!(store.rebuild_pending().is_some());
        assert_eq!(keys.key_count(), 1);
    }

    #[test]
    fn retry_promotes_a_candidate_whose_key_store_reported_failure_after_commit() {
        let (keys, store, _, old_live) = initialized_with_secret();
        keys.fail_next_store_after_commit(KeyProviderErrorKind::BackendFailure);
        let mut confirmer = ScriptedConfirmer::accepting();

        assert!(matches!(
            RebuildOperations::new(&keys, &store).rebuild(INTERACTION, &mut confirmer),
            Err(RebuildError::SecureStore(error))
                if error.kind() == KeyProviderErrorKind::BackendFailure
        ));
        let candidate = store.rebuild_pending().unwrap();
        let candidate_key_id = inspect_envelope(&candidate).unwrap().key_id;
        assert!(keys.contains(&candidate_key_id));
        assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
        assert_eq!(keys.store_calls(), 2);

        let mut confirmer = ScriptedConfirmer::accepting();
        let receipt = RebuildOperations::new(&keys, &store)
            .rebuild(INTERACTION, &mut confirmer)
            .unwrap();
        assert_eq!(receipt.key_id, candidate_key_id);
        assert_eq!(store.live().as_deref(), Some(candidate.as_slice()));
        assert!(store.rebuild_pending().is_none());
        assert_eq!(keys.store_calls(), 2);
        assert_eq!(keys.key_count(), 2);
    }

    #[test]
    fn verified_indeterminate_recovery_commit_can_safely_continue() {
        let (keys, store, _, _) = initialized_with_secret();
        store.fail_next_recovery_preservation(RecoveryPreservationFault::IndeterminateAfterCommit);
        let mut confirmer = ScriptedConfirmer::accepting();

        assert!(
            RebuildOperations::new(&keys, &store)
                .rebuild(INTERACTION, &mut confirmer)
                .is_ok()
        );
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(bundles.len(), 1);
    }

    #[test]
    fn recovery_failure_never_creates_a_candidate_or_new_key() {
        for fault in [
            RecoveryPreservationFault::NotCommitted,
            RecoveryPreservationFault::IndeterminateBeforeCommit,
        ] {
            let (keys, store, _, old_live) = initialized_with_secret();
            store.fail_next_recovery_preservation(fault);
            let mut confirmer = ScriptedConfirmer::accepting();
            assert!(
                RebuildOperations::new(&keys, &store)
                    .rebuild(INTERACTION, &mut confirmer)
                    .is_err()
            );
            assert_eq!(store.live().as_deref(), Some(old_live.as_slice()));
            assert!(store.rebuild_pending().is_none());
            assert_eq!(keys.key_count(), 1);
        }
    }
}
