#![forbid(unsafe_code)]

use std::{error::Error, fmt, time::SystemTime};

use crate::{
    EnvelopeError, KeyId, MasterKey, VaultId,
    confirmation::{ConfirmationError, TypedConfirmationRequest, TypedConfirmer},
    inspect_envelope,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderError, KeyProviderErrorKind},
    open_envelope,
    vault_store::{
        CommitOutcome, RecoveryArtifacts, RecoveryBundleId, RecoveryBundleMetadata, RecoveryReason,
        VaultStore, VaultStoreError, VaultStoreErrorKind, VaultTransaction,
    },
};

const MAX_RECOVERY_ID_ATTEMPTS: usize = 8;
const RESTORE_CONFIRMATION: TypedConfirmationRequest = TypedConfirmationRequest {
    expected: "RESTORE",
    action: "restore the selected encrypted vault",
    warning: "The current encrypted vault will be retained as an internal recovery bundle before it is replaced.",
};
const RECOVERY_RESTORE_CONFIRMATION: TypedConfirmationRequest = TypedConfirmationRequest {
    expected: "RESTORE",
    action: "restore the selected internal recovery bundle",
    warning: "This explicitly changes the live vault. Any current encrypted vault will first be retained as another recovery bundle.",
};

/// Safe metadata confirming an exact authenticated restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RestoreReceipt {
    pub(crate) revision: u64,
    pub(crate) displaced_to: Option<RecoveryBundleId>,
}

/// Portable failures while reading a user-selected encrypted restore source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestoreSourceError {
    UnsafePath,
    NotFound,
    PermissionDenied,
    IoFailure,
}

impl RestoreSourceError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::UnsafePath | Self::PermissionDenied => 13,
            Self::NotFound | Self::IoFailure => 1,
        }
    }
}

impl fmt::Display for RestoreSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "the encrypted restore source path is unsafe",
            Self::NotFound => "the encrypted restore source does not exist",
            Self::PermissionDenied => "permission to read the encrypted restore source was denied",
            Self::IoFailure => "the encrypted restore source could not be read",
        })
    }
}

impl Error for RestoreSourceError {}

/// Value- and name-free restore failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestoreError {
    SecureStore(KeyProviderError),
    VaultKeyMissing,
    InvalidKeyMaterial,
    SourceEnvelope(EnvelopeError),
    CurrentEnvelope(EnvelopeError),
    VaultIdentityMismatch,
    ConflictingInitialization,
    RecoveryBundleNotFound,
    RecoveryBundleNotRestorable,
    Confirmation(ConfirmationError),
    Store(VaultStoreError),
    RecoveryNotCommitted,
    RecoveryOutcomeIndeterminate,
    CommitNotCompleted,
    CommitOutcomeIndeterminate,
}

impl RestoreError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::SecureStore(_) => 11,
            Self::VaultKeyMissing
            | Self::InvalidKeyMaterial
            | Self::SourceEnvelope(_)
            | Self::CurrentEnvelope(_) => 12,
            Self::VaultIdentityMismatch
            | Self::ConflictingInitialization
            | Self::RecoveryBundleNotFound
            | Self::RecoveryBundleNotRestorable => 14,
            Self::Confirmation(error) => error.exit_code(),
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

impl From<VaultStoreError> for RestoreError {
    fn from(error: VaultStoreError) -> Self {
        if error.kind() == VaultStoreErrorKind::OutcomeIndeterminate {
            Self::CommitOutcomeIndeterminate
        } else {
            Self::Store(error)
        }
    }
}

impl From<ConfirmationError> for RestoreError {
    fn from(error: ConfirmationError) -> Self {
        Self::Confirmation(error)
    }
}

impl fmt::Display for RestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SecureStore(_) => "secure-store access failed",
            Self::VaultKeyMissing => "the selected vault's secure-store key is missing",
            Self::InvalidKeyMaterial => "the selected vault's secure-store key is invalid",
            Self::SourceEnvelope(_) => "the selected encrypted restore source is unreadable",
            Self::CurrentEnvelope(_) => {
                "the current vault identity cannot be established safely; nothing was changed"
            }
            Self::VaultIdentityMismatch => {
                "the selected vault has a different identity; nothing was changed"
            }
            Self::ConflictingInitialization => {
                "a reserved initialization candidate must be resolved before restore"
            }
            Self::RecoveryBundleNotFound => "the selected recovery bundle was not found",
            Self::RecoveryBundleNotRestorable => {
                "the selected recovery bundle has no restorable live vault"
            }
            Self::Confirmation(_) => "restore was not confirmed; nothing was changed",
            Self::Store(_) => "the local vault or recovery store failed",
            Self::RecoveryNotCommitted => {
                "the current vault could not be preserved; nothing was replaced"
            }
            Self::RecoveryOutcomeIndeterminate => {
                "recovery preservation is indeterminate; the live vault was not replaced"
            }
            Self::CommitNotCompleted => "the selected vault was not installed",
            Self::CommitOutcomeIndeterminate => {
                "the restore outcome is indeterminate; inspect the live vault before retrying"
            }
        })
    }
}

impl Error for RestoreError {}

#[derive(Clone, Copy)]
enum RestorePolicy {
    ExternalBackup,
    InternalRecovery,
}

/// Authenticated restore policy over injected secure-key and transactional-store seams.
pub(crate) struct RestoreOperations<'dependencies, K, S> {
    keys: &'dependencies K,
    store: &'dependencies S,
}

impl<'dependencies, K, S> RestoreOperations<'dependencies, K, S>
where
    K: KeyProvider,
    S: VaultStore,
{
    pub(crate) const fn new(keys: &'dependencies K, store: &'dependencies S) -> Self {
        Self { keys, store }
    }

    pub(crate) fn restore_external(
        &self,
        envelope: &[u8],
        interaction: InteractionPolicy,
        confirmer: &mut dyn TypedConfirmer,
    ) -> Result<RestoreReceipt, RestoreError> {
        self.store.initialization_transaction(|transaction| {
            self.restore_locked(
                transaction,
                envelope,
                interaction,
                RestorePolicy::ExternalBackup,
                confirmer,
            )
        })
    }

    pub(crate) fn restore_bundle(
        &self,
        bundle_id: RecoveryBundleId,
        interaction: InteractionPolicy,
        confirmer: &mut dyn TypedConfirmer,
    ) -> Result<RestoreReceipt, RestoreError> {
        self.store.initialization_transaction(|transaction| {
            let bundle = transaction
                .read_recovery_bundles()?
                .into_iter()
                .find(|bundle| bundle.metadata.id == bundle_id)
                .ok_or(RestoreError::RecoveryBundleNotFound)?;
            let envelope = bundle
                .live
                .as_ref()
                .ok_or(RestoreError::RecoveryBundleNotRestorable)?;
            if let Some(pending) = &bundle.init_pending {
                let (opened, key) = self.open_source(pending, interaction)?;
                drop(opened);
                drop(key);
            }
            self.restore_locked(
                transaction,
                envelope,
                interaction,
                RestorePolicy::InternalRecovery,
                confirmer,
            )
        })
    }

    fn restore_locked(
        &self,
        transaction: &mut dyn VaultTransaction,
        source: &[u8],
        interaction: InteractionPolicy,
        policy: RestorePolicy,
        confirmer: &mut dyn TypedConfirmer,
    ) -> Result<RestoreReceipt, RestoreError> {
        let (opened, key) = self.open_source(source, interaction)?;
        let expected_vault_id = opened.vault_id;
        let expected_key_id = opened.key_id;
        let expected_revision = opened.vault.revision();
        drop(opened);

        if transaction.read_init_pending()?.is_some() {
            return Err(RestoreError::ConflictingInitialization);
        }
        let current = transaction.read_live()?;
        if let Some(current) = &current
            && matches!(policy, RestorePolicy::ExternalBackup)
        {
            let metadata = inspect_envelope(current).map_err(RestoreError::CurrentEnvelope)?;
            if metadata.vault_id != expected_vault_id {
                return Err(RestoreError::VaultIdentityMismatch);
            }
        }

        if current.is_some() || matches!(policy, RestorePolicy::InternalRecovery) {
            let request = match policy {
                RestorePolicy::ExternalBackup => RESTORE_CONFIRMATION,
                RestorePolicy::InternalRecovery => RECOVERY_RESTORE_CONFIRMATION,
            };
            confirmer.confirm(request)?;
        }

        let displaced_to = current
            .as_ref()
            .map(|current| Self::preserve_live(transaction, current))
            .transpose()?;
        let outcome = if current.is_some() {
            transaction.replace_live(source)?
        } else {
            transaction.install_live(source)?
        };
        Self::verify_live_commit(
            transaction,
            outcome,
            source,
            &key,
            expected_vault_id,
            expected_key_id,
            expected_revision,
        )?;
        Ok(RestoreReceipt {
            revision: expected_revision,
            displaced_to,
        })
    }

    fn open_source(
        &self,
        envelope: &[u8],
        interaction: InteractionPolicy,
    ) -> Result<(crate::OpenedVault, MasterKey), RestoreError> {
        let metadata = inspect_envelope(envelope).map_err(RestoreError::SourceEnvelope)?;
        let key = self
            .keys
            .load(&metadata.key_id, interaction)
            .map_err(RestoreError::from_key_provider)?;
        let opened = open_envelope(envelope, &key).map_err(RestoreError::SourceEnvelope)?;
        Ok((opened, key))
    }

    fn preserve_live(
        transaction: &mut dyn VaultTransaction,
        live: &[u8],
    ) -> Result<RecoveryBundleId, RestoreError> {
        let created_at_unix_seconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| VaultStoreError::new(VaultStoreErrorKind::IoFailure))?
            .as_secs();
        for _ in 0..MAX_RECOVERY_ID_ATTEMPTS {
            let metadata = RecoveryBundleMetadata {
                id: RecoveryBundleId::generate()?,
                created_at_unix_seconds,
                reason: RecoveryReason::Restore,
            };
            let outcome = match transaction.preserve_recovery(
                metadata,
                RecoveryArtifacts {
                    live: Some(live),
                    init_pending: None,
                },
            ) {
                Err(error) if error.kind() == VaultStoreErrorKind::Conflict => continue,
                result => result?,
            };
            if outcome == CommitOutcome::NotCommitted {
                return Err(RestoreError::RecoveryNotCommitted);
            }
            if outcome == CommitOutcome::Indeterminate {
                return Err(RestoreError::RecoveryOutcomeIndeterminate);
            }
            let preserved = transaction
                .read_recovery_bundles()?
                .into_iter()
                .find(|bundle| bundle.metadata.id == metadata.id);
            if preserved.is_some_and(|bundle| {
                bundle.metadata == metadata
                    && bundle
                        .live
                        .as_ref()
                        .is_some_and(|bytes| bytes.as_slice() == live)
                    && bundle.init_pending.is_none()
            }) {
                return Ok(metadata.id);
            }
            return Err(RestoreError::RecoveryOutcomeIndeterminate);
        }
        Err(VaultStoreError::new(VaultStoreErrorKind::Conflict).into())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_live_commit(
        transaction: &mut dyn VaultTransaction,
        outcome: CommitOutcome,
        expected_envelope: &[u8],
        key: &MasterKey,
        expected_vault_id: VaultId,
        expected_key_id: KeyId,
        expected_revision: u64,
    ) -> Result<(), RestoreError> {
        if outcome == CommitOutcome::NotCommitted {
            return Err(RestoreError::CommitNotCompleted);
        }
        let Some(committed) = transaction.read_live()? else {
            return Err(RestoreError::CommitOutcomeIndeterminate);
        };
        if committed.as_slice() != expected_envelope {
            return Err(RestoreError::CommitOutcomeIndeterminate);
        }
        let opened =
            open_envelope(&committed, key).map_err(|_| RestoreError::CommitOutcomeIndeterminate)?;
        if opened.vault_id != expected_vault_id
            || opened.key_id != expected_key_id
            || opened.vault.revision() != expected_revision
        {
            return Err(RestoreError::CommitOutcomeIndeterminate);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProfileName,
        confirmation::TypedConfirmationRequest,
        init::Initializer,
        profiles::ProfileOperations,
        testing::{
            MemoryKeyProvider, MemoryVaultStore, RecoveryPreservationFault, ReplacementFault,
        },
        vault_store::{RecoveryArtifacts, RecoveryBundleMetadata, VaultStore},
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
            assert_eq!(request.expected, "RESTORE");
            self.result
        }
    }

    fn initialized() -> (MemoryKeyProvider, MemoryVaultStore) {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        (keys, store)
    }

    fn changed_live(keys: &MemoryKeyProvider, store: &MemoryVaultStore) -> Vec<u8> {
        ProfileOperations::new(keys, store)
            .create(ProfileName::new("changed").unwrap(), INTERACTION)
            .unwrap();
        store.live().unwrap()
    }

    #[test]
    fn restore_preserves_the_displaced_exact_live_before_rollback() {
        let (keys, store) = initialized();
        let backup = store.live().unwrap();
        let displaced = changed_live(&keys, &store);
        let mut confirmer = ScriptedConfirmer::accepting();

        let receipt = RestoreOperations::new(&keys, &store)
            .restore_external(&backup, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(store.live().as_deref(), Some(backup.as_slice()));
        assert_eq!(receipt.revision, 0);
        assert!(receipt.displaced_to.is_some());
        assert_eq!(confirmer.calls, 1);
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(bundles.len(), 1);
        assert_eq!(
            bundles[0].live.as_ref().unwrap().as_slice(),
            displaced.as_slice()
        );
        assert_eq!(bundles[0].metadata.reason, RecoveryReason::Restore);
    }

    #[test]
    fn external_restore_preserves_a_same_identity_live_vault_that_no_longer_authenticates() {
        let (keys, store) = initialized();
        let backup = store.live().unwrap();
        let mut corrupt = backup.clone();
        let last = corrupt.last_mut().unwrap();
        *last ^= 0x80;
        store.set_live(corrupt.clone());
        let mut confirmer = ScriptedConfirmer::accepting();

        RestoreOperations::new(&keys, &store)
            .restore_external(&backup, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(store.live().as_deref(), Some(backup.as_slice()));
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(bundles[0].live.as_ref().unwrap().as_slice(), corrupt);
    }

    #[test]
    fn restore_without_a_live_vault_needs_no_confirmation() {
        let keys = MemoryKeyProvider::new();
        let source_store = MemoryVaultStore::new();
        Initializer::new(&keys, &source_store)
            .initialize(INTERACTION)
            .unwrap();
        let backup = source_store.live().unwrap();
        let destination = MemoryVaultStore::new();
        let mut confirmer = ScriptedConfirmer::rejecting();

        let receipt = RestoreOperations::new(&keys, &destination)
            .restore_external(&backup, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(destination.live().as_deref(), Some(backup.as_slice()));
        assert_eq!(receipt.displaced_to, None);
        assert_eq!(confirmer.calls, 0);
    }

    #[test]
    fn mismatch_rejection_and_pending_state_never_change_the_live_vault() {
        let (keys, store) = initialized();
        let original = store.live().unwrap();
        let other_store = MemoryVaultStore::new();
        Initializer::new(&keys, &other_store)
            .initialize(INTERACTION)
            .unwrap();
        let other = other_store.live().unwrap();
        let mut confirmer = ScriptedConfirmer::accepting();
        assert_eq!(
            RestoreOperations::new(&keys, &store)
                .restore_external(&other, INTERACTION, &mut confirmer)
                .unwrap_err(),
            RestoreError::VaultIdentityMismatch
        );
        assert_eq!(confirmer.calls, 0);
        assert_eq!(store.live().as_deref(), Some(original.as_slice()));

        store.set_pending(b"reserved-pending".to_vec());
        assert_eq!(
            RestoreOperations::new(&keys, &store)
                .restore_external(&original, INTERACTION, &mut confirmer)
                .unwrap_err(),
            RestoreError::ConflictingInitialization
        );
        assert_eq!(confirmer.calls, 0);
        assert_eq!(store.live().as_deref(), Some(original.as_slice()));
    }

    #[test]
    fn source_key_failure_and_missing_bundle_do_not_confirm_or_mutate() {
        let (keys, store) = initialized();
        let backup = store.live().unwrap();
        let displaced = changed_live(&keys, &store);
        keys.fail_next_load(KeyProviderErrorKind::InteractionRequired);
        let mut confirmer = ScriptedConfirmer::accepting();

        assert!(matches!(
            RestoreOperations::new(&keys, &store)
                .restore_external(&backup, INTERACTION, &mut confirmer),
            Err(RestoreError::SecureStore(error))
                if error.kind() == KeyProviderErrorKind::InteractionRequired
        ));
        assert_eq!(store.live().as_deref(), Some(displaced.as_slice()));
        assert_eq!(confirmer.calls, 0);
        assert_eq!(
            RestoreOperations::new(&keys, &store)
                .restore_bundle(
                    RecoveryBundleId::from_bytes([0x99; 16]),
                    INTERACTION,
                    &mut confirmer,
                )
                .unwrap_err(),
            RestoreError::RecoveryBundleNotFound
        );
        assert_eq!(store.live().as_deref(), Some(displaced.as_slice()));
        assert_eq!(confirmer.calls, 0);
    }

    #[test]
    fn rejected_confirmation_and_failed_preservation_keep_live_exactly_unchanged() {
        let (keys, store) = initialized();
        let backup = store.live().unwrap();
        let displaced = changed_live(&keys, &store);
        let mut rejected = ScriptedConfirmer::rejecting();
        assert_eq!(
            RestoreOperations::new(&keys, &store)
                .restore_external(&backup, INTERACTION, &mut rejected)
                .unwrap_err(),
            RestoreError::Confirmation(ConfirmationError::Rejected)
        );
        assert_eq!(store.live().as_deref(), Some(displaced.as_slice()));

        store.fail_next_recovery_preservation(RecoveryPreservationFault::NotCommitted);
        let mut accepted = ScriptedConfirmer::accepting();
        assert_eq!(
            RestoreOperations::new(&keys, &store)
                .restore_external(&backup, INTERACTION, &mut accepted)
                .unwrap_err(),
            RestoreError::RecoveryNotCommitted
        );
        assert_eq!(store.live().as_deref(), Some(displaced.as_slice()));
    }

    #[test]
    fn indeterminate_preservation_aborts_before_live_replacement() {
        let (keys, store) = initialized();
        let backup = store.live().unwrap();
        let displaced = changed_live(&keys, &store);
        store.fail_next_recovery_preservation(RecoveryPreservationFault::IndeterminateAfterCommit);
        let mut confirmer = ScriptedConfirmer::accepting();

        assert_eq!(
            RestoreOperations::new(&keys, &store)
                .restore_external(&backup, INTERACTION, &mut confirmer)
                .unwrap_err(),
            RestoreError::RecoveryOutcomeIndeterminate
        );
        assert_eq!(store.live().as_deref(), Some(displaced.as_slice()));
    }

    #[test]
    fn indeterminate_live_install_is_resolved_from_exact_committed_state() {
        let (keys, store) = initialized();
        let backup = store.live().unwrap();
        changed_live(&keys, &store);
        store.fail_next_replacement(ReplacementFault::IndeterminateAfterCommit);
        let mut confirmer = ScriptedConfirmer::accepting();

        RestoreOperations::new(&keys, &store)
            .restore_external(&backup, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(store.live().as_deref(), Some(backup.as_slice()));
    }

    #[test]
    fn failed_live_install_keeps_the_new_recovery_escape_hatch() {
        let (keys, store) = initialized();
        let backup = store.live().unwrap();
        let displaced = changed_live(&keys, &store);
        store.fail_next_replacement(ReplacementFault::NotCommitted);
        let mut confirmer = ScriptedConfirmer::accepting();

        assert_eq!(
            RestoreOperations::new(&keys, &store)
                .restore_external(&backup, INTERACTION, &mut confirmer)
                .unwrap_err(),
            RestoreError::CommitNotCompleted
        );
        assert_eq!(store.live().as_deref(), Some(displaced.as_slice()));
        assert_eq!(
            store
                .shared_read::<_, VaultStoreError, _>(|read| {
                    Ok(read.read_recovery_bundles()?.len())
                })
                .unwrap(),
            1
        );
    }

    #[test]
    fn recovery_restore_keeps_the_selected_bundle_and_preserves_displaced_live() {
        let (keys, store) = initialized();
        let other_store = MemoryVaultStore::new();
        Initializer::new(&keys, &other_store)
            .initialize(INTERACTION)
            .unwrap();
        let selected = other_store.live().unwrap();
        let selected_id = RecoveryBundleId::from_bytes([0x44; 16]);
        store
            .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                transaction.preserve_recovery(
                    RecoveryBundleMetadata {
                        id: selected_id,
                        created_at_unix_seconds: 1,
                        reason: RecoveryReason::Rebuild,
                    },
                    RecoveryArtifacts {
                        live: Some(&selected),
                        init_pending: None,
                    },
                )?;
                Ok(())
            })
            .unwrap();
        let displaced = b"unreadable-current-live".to_vec();
        store.set_live(displaced.clone());
        let mut confirmer = ScriptedConfirmer::accepting();

        RestoreOperations::new(&keys, &store)
            .restore_bundle(selected_id, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(store.live().as_deref(), Some(selected.as_slice()));
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(bundles.len(), 2);
        assert!(
            bundles
                .iter()
                .any(|bundle| bundle.metadata.id == selected_id)
        );
        assert!(bundles.iter().any(|bundle| {
            bundle.metadata.id != selected_id
                && bundle.live.as_ref().unwrap().as_slice() == displaced
        }));
        assert_eq!(confirmer.calls, 1);
    }

    #[test]
    fn recovery_restore_requires_confirmation_even_when_no_live_vault_exists() {
        let (keys, store) = initialized();
        let selected = store.live().unwrap();
        let selected_id = RecoveryBundleId::from_bytes([0x55; 16]);
        store
            .exclusive_transaction::<_, VaultStoreError, _>(|transaction| {
                transaction.preserve_recovery(
                    RecoveryBundleMetadata {
                        id: selected_id,
                        created_at_unix_seconds: 1,
                        reason: RecoveryReason::Reset,
                    },
                    RecoveryArtifacts {
                        live: Some(&selected),
                        init_pending: None,
                    },
                )?;
                Ok(())
            })
            .unwrap();
        store.clear_live();
        let mut confirmer = ScriptedConfirmer::rejecting();

        assert_eq!(
            RestoreOperations::new(&keys, &store)
                .restore_bundle(selected_id, INTERACTION, &mut confirmer)
                .unwrap_err(),
            RestoreError::Confirmation(ConfirmationError::Rejected)
        );
        assert!(store.live().is_none());
        assert_eq!(confirmer.calls, 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn local_restore_round_trip_preserves_source_and_displaced_ciphertext() {
        use std::{fs, os::unix::fs::DirBuilderExt};

        use crate::platform::macos::{
            EncryptedBackupWriter, EncryptedRestoreSource, LocalVaultStore,
        };

        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "gschrank-restore-round-trip-{}-{}",
                std::process::id(),
                RecoveryBundleId::generate().unwrap().to_hex()
            ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&root).unwrap();
        let data = root.join("data");
        let source = root.join("vault.backup");
        let keys = MemoryKeyProvider::new();
        let store = LocalVaultStore::new(data);
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let backup = store
            .shared_read::<_, VaultStoreError, _>(|read| {
                read.read_live()?
                    .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))
            })
            .unwrap();
        EncryptedBackupWriter::new(source.clone())
            .create(&backup)
            .unwrap();
        ProfileOperations::new(&keys, &store)
            .create(ProfileName::new("changed").unwrap(), INTERACTION)
            .unwrap();
        let displaced = store
            .shared_read::<_, VaultStoreError, _>(|read| {
                read.read_live()?
                    .ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))
            })
            .unwrap();
        let restore_source = EncryptedRestoreSource::new(source.clone()).read().unwrap();
        let mut confirmer = ScriptedConfirmer::accepting();

        RestoreOperations::new(&keys, &store)
            .restore_external(&restore_source, INTERACTION, &mut confirmer)
            .unwrap();

        assert_eq!(fs::read(&source).unwrap(), backup.as_slice());
        let bundles = store
            .shared_read::<_, VaultStoreError, _>(|read| read.read_recovery_bundles())
            .unwrap();
        assert_eq!(
            bundles[0].live.as_ref().unwrap().as_slice(),
            displaced.as_slice()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
