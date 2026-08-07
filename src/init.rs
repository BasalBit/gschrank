#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use crate::{
    EnvelopeError, KeyId, MasterKey, Vault, VaultId, inspect_envelope,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderError, KeyProviderErrorKind},
    open_envelope, seal_vault,
    vault_store::{
        CommitOutcome, VaultStore, VaultStoreError, VaultStoreErrorKind, VaultTransaction,
    },
};

const MAX_ID_COLLISION_RETRIES: usize = 8;

/// The safe result of explicit initialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitOutcome {
    Created {
        vault_id: VaultId,
        key_id: KeyId,
    },
    AlreadyInitialized {
        vault_id: VaultId,
        key_id: KeyId,
        revision: u64,
    },
}

/// A value-free initialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InitError {
    SecureStore(KeyProviderError),
    VaultKeyMissing,
    InvalidKeyMaterial,
    Vault(EnvelopeError),
    Store(VaultStoreError),
    CommitNotCompleted,
    CommitOutcomeIndeterminate,
}

impl InitError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
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
            Self::CommitNotCompleted => 1,
            Self::CommitOutcomeIndeterminate => 15,
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

impl From<VaultStoreError> for InitError {
    fn from(error: VaultStoreError) -> Self {
        if error.kind() == VaultStoreErrorKind::OutcomeIndeterminate {
            Self::CommitOutcomeIndeterminate
        } else {
            Self::Store(error)
        }
    }
}

impl From<EnvelopeError> for InitError {
    fn from(error: EnvelopeError) -> Self {
        Self::Vault(error)
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SecureStore(_) => "secure-store access failed",
            Self::VaultKeyMissing => "the vault's secure-store key is missing",
            Self::InvalidKeyMaterial => "the vault's secure-store key is invalid",
            Self::Vault(_) => "the encrypted vault is unreadable",
            Self::Store(_) => "the local vault store failed",
            Self::CommitNotCompleted => "vault initialization did not commit",
            Self::CommitOutcomeIndeterminate => "vault initialization outcome is indeterminate",
        })
    }
}

impl Error for InitError {}

/// Explicit initialization policy over injected secure-store and vault-store adapters.
pub(crate) struct Initializer<'dependencies, K, S> {
    keys: &'dependencies K,
    store: &'dependencies S,
}

impl<'dependencies, K, S> Initializer<'dependencies, K, S>
where
    K: KeyProvider,
    S: VaultStore,
{
    pub(crate) const fn new(keys: &'dependencies K, store: &'dependencies S) -> Self {
        Self { keys, store }
    }

    pub(crate) fn initialize(
        &self,
        interaction: InteractionPolicy,
    ) -> Result<InitOutcome, InitError> {
        self.store.initialization_transaction(|transaction| {
            self.initialize_locked(transaction, interaction)
        })
    }

    fn initialize_locked(
        &self,
        transaction: &mut dyn VaultTransaction,
        interaction: InteractionPolicy,
    ) -> Result<InitOutcome, InitError> {
        if let Some(live) = transaction.read_live()? {
            return self.validate_live(&live, interaction);
        }

        if transaction.read_rebuild_pending()?.is_some() {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict).into());
        }

        if let Some(pending) = transaction.read_init_pending()? {
            return self.resume_pending(transaction, &pending, interaction);
        }

        self.create_fresh(transaction, interaction)
    }

    fn validate_live(
        &self,
        live: &[u8],
        interaction: InteractionPolicy,
    ) -> Result<InitOutcome, InitError> {
        let metadata = inspect_envelope(live)?;
        let key = self
            .keys
            .load(&metadata.key_id, interaction)
            .map_err(InitError::from_key_provider)?;
        let opened = open_envelope(live, &key)?;
        Ok(InitOutcome::AlreadyInitialized {
            vault_id: opened.vault_id,
            key_id: opened.key_id,
            revision: opened.vault.revision(),
        })
    }

    fn resume_pending(
        &self,
        transaction: &mut dyn VaultTransaction,
        pending: &[u8],
        interaction: InteractionPolicy,
    ) -> Result<InitOutcome, InitError> {
        let metadata = inspect_envelope(pending)?;
        let key = match self.keys.load(&metadata.key_id, interaction) {
            Ok(key) => key,
            Err(error) if error.kind() == KeyProviderErrorKind::NotFound => {
                transaction.discard_init_pending()?;
                return self.create_fresh(transaction, interaction);
            }
            Err(error) => return Err(InitError::from_key_provider(error)),
        };

        let opened = open_envelope(pending, &key)?;
        promote_and_verify(transaction, &key, opened.vault_id, opened.key_id)
    }

    fn create_fresh(
        &self,
        transaction: &mut dyn VaultTransaction,
        interaction: InteractionPolicy,
    ) -> Result<InitOutcome, InitError> {
        initialize_empty_locked(self.keys, transaction, interaction)
    }
}

/// Create a new empty vault while the caller retains the exclusive store lock.
///
/// Lifecycle operations use this only after they have established that both
/// root artifacts are absent. The ordinary initializer performs that same
/// check before delegating here.
pub(crate) fn initialize_empty_locked<K>(
    keys: &K,
    transaction: &mut dyn VaultTransaction,
    interaction: InteractionPolicy,
) -> Result<InitOutcome, InitError>
where
    K: KeyProvider,
{
    for _ in 0..MAX_ID_COLLISION_RETRIES {
        let vault_id = VaultId::generate()?;
        let key_id = KeyId::generate()?;
        let key = MasterKey::generate()?;
        let envelope = seal_vault(&Vault::empty(), vault_id, key_id, &key)?;
        transaction.create_init_pending(&envelope)?;

        match keys.store_new(&key_id, &key, interaction) {
            Ok(()) => return promote_and_verify(transaction, &key, vault_id, key_id),
            Err(error) if error.kind() == KeyProviderErrorKind::AlreadyExists => {
                transaction.discard_init_pending()?;
            }
            Err(error) => {
                if error.definitely_did_not_store() {
                    transaction.discard_init_pending()?;
                }
                return Err(InitError::from_key_provider(error));
            }
        }
    }

    Err(InitError::SecureStore(KeyProviderError::new(
        KeyProviderErrorKind::AlreadyExists,
    )))
}

fn promote_and_verify(
    transaction: &mut dyn VaultTransaction,
    key: &MasterKey,
    expected_vault_id: VaultId,
    expected_key_id: KeyId,
) -> Result<InitOutcome, InitError> {
    match transaction.promote_init_pending()? {
        CommitOutcome::Committed => {}
        CommitOutcome::NotCommitted => return Err(InitError::CommitNotCompleted),
        CommitOutcome::Indeterminate => {
            let Some(live) = transaction.read_live()? else {
                return Err(InitError::CommitOutcomeIndeterminate);
            };
            let opened =
                open_envelope(&live, key).map_err(|_| InitError::CommitOutcomeIndeterminate)?;
            if opened.vault_id != expected_vault_id || opened.key_id != expected_key_id {
                return Err(InitError::CommitOutcomeIndeterminate);
            }
            return Ok(InitOutcome::Created {
                vault_id: opened.vault_id,
                key_id: opened.key_id,
            });
        }
    }

    let live = transaction
        .read_live()?
        .ok_or(InitError::CommitOutcomeIndeterminate)?;
    let opened = open_envelope(&live, key)?;
    if opened.vault_id != expected_vault_id || opened.key_id != expected_key_id {
        return Err(InitError::Vault(EnvelopeError::AuthenticationFailed));
    }
    Ok(InitOutcome::Created {
        vault_id: opened.vault_id,
        key_id: opened.key_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        testing::{MemoryKeyProvider, MemoryVaultStore, PromotionFault},
        vault_store::VaultStoreErrorKind,
    };

    const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;

    #[test]
    fn creates_and_reopens_an_empty_revision_zero_vault() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        let initializer = Initializer::new(&keys, &store);

        let InitOutcome::Created { vault_id, key_id } =
            initializer.initialize(INTERACTION).unwrap()
        else {
            panic!("expected a new vault");
        };
        assert!(store.pending().is_none());
        assert!(store.live().is_some());
        assert!(keys.contains(&key_id));

        assert_eq!(
            initializer.initialize(INTERACTION).unwrap(),
            InitOutcome::AlreadyInitialized {
                vault_id,
                key_id,
                revision: 0,
            }
        );
        assert_eq!(keys.key_count(), 1);
        assert_eq!(keys.store_calls(), 1);
    }

    #[test]
    fn clean_key_store_failure_removes_the_pending_envelope() {
        let keys = MemoryKeyProvider::new();
        keys.fail_next_store(KeyProviderErrorKind::UserCancelled);
        let store = MemoryVaultStore::new();
        let error = Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap_err();

        assert_eq!(error.exit_code(), 11);
        assert!(store.live().is_none());
        assert!(store.pending().is_none());
        assert_eq!(keys.key_count(), 0);
    }

    #[test]
    fn ambiguous_key_store_failure_preserves_pending_state() {
        let keys = MemoryKeyProvider::new();
        keys.fail_next_store(KeyProviderErrorKind::BackendFailure);
        let store = MemoryVaultStore::new();
        let error = Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap_err();

        assert_eq!(error.exit_code(), 11);
        assert!(store.live().is_none());
        assert!(store.pending().is_some());
    }

    #[test]
    fn repeated_init_resumes_a_pending_envelope_with_its_existing_key() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        store.fail_next_promotion(PromotionFault::NotCommitted);
        let initializer = Initializer::new(&keys, &store);

        assert_eq!(
            initializer.initialize(INTERACTION).unwrap_err(),
            InitError::CommitNotCompleted
        );
        assert!(store.live().is_none());
        assert!(store.pending().is_some());
        assert_eq!(keys.key_count(), 1);

        assert!(matches!(
            initializer.initialize(INTERACTION).unwrap(),
            InitOutcome::Created { .. }
        ));
        assert!(store.live().is_some());
        assert!(store.pending().is_none());
        assert_eq!(keys.key_count(), 1);
        assert_eq!(keys.store_calls(), 1);
    }

    #[test]
    fn definitively_missing_pending_key_is_discarded_before_a_fresh_attempt() {
        let old_key = MasterKey::from_bytes([7; 32]);
        let pending = seal_vault(
            &Vault::empty(),
            VaultId::from_bytes([8; 16]),
            KeyId::from_bytes([9; 16]),
            &old_key,
        )
        .unwrap();
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        store.set_pending(pending.to_vec());

        assert!(matches!(
            Initializer::new(&keys, &store)
                .initialize(INTERACTION)
                .unwrap(),
            InitOutcome::Created { .. }
        ));
        assert!(store.live().is_some());
        assert!(store.pending().is_none());
        assert_eq!(keys.key_count(), 1);
    }

    #[test]
    fn temporarily_inaccessible_pending_key_preserves_the_pending_envelope() {
        let key_id = KeyId::from_bytes([9; 16]);
        let key = MasterKey::from_bytes([7; 32]);
        let pending =
            seal_vault(&Vault::empty(), VaultId::from_bytes([8; 16]), key_id, &key).unwrap();
        let keys = MemoryKeyProvider::new();
        keys.insert(key_id, &key);
        keys.fail_next_load(KeyProviderErrorKind::InteractionRequired);
        let store = MemoryVaultStore::new();
        store.set_pending(pending.to_vec());

        let error = Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap_err();
        assert_eq!(error.exit_code(), 11);
        assert!(store.live().is_none());
        assert_eq!(store.pending().as_deref(), Some(pending.as_slice()));
        assert_eq!(keys.store_calls(), 0);
    }

    #[test]
    fn pending_envelope_that_fails_authentication_is_frozen() {
        let key_id = KeyId::from_bytes([9; 16]);
        let original_key = MasterKey::from_bytes([7; 32]);
        let wrong_key = MasterKey::from_bytes([6; 32]);
        let pending = seal_vault(
            &Vault::empty(),
            VaultId::from_bytes([8; 16]),
            key_id,
            &original_key,
        )
        .unwrap();
        let keys = MemoryKeyProvider::new();
        keys.insert(key_id, &wrong_key);
        let store = MemoryVaultStore::new();
        store.set_pending(pending.to_vec());

        let error = Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap_err();
        assert_eq!(error.exit_code(), 12);
        assert!(store.live().is_none());
        assert_eq!(store.pending().as_deref(), Some(pending.as_slice()));
        assert_eq!(keys.store_calls(), 0);
    }

    #[test]
    fn corrupt_live_vault_is_frozen_without_creating_a_key() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        store.set_live(b"not a vault".to_vec());

        let error = Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap_err();
        assert_eq!(error.exit_code(), 12);
        assert_eq!(keys.key_count(), 0);
        assert_eq!(keys.store_calls(), 0);
        assert_eq!(store.live().unwrap(), b"not a vault");
    }

    #[test]
    fn live_vault_with_missing_key_is_never_reinitialized() {
        let key = MasterKey::from_bytes([3; 32]);
        let envelope = seal_vault(
            &Vault::empty(),
            VaultId::from_bytes([1; 16]),
            KeyId::from_bytes([2; 16]),
            &key,
        )
        .unwrap();
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        store.set_live(envelope.to_vec());

        assert_eq!(
            Initializer::new(&keys, &store)
                .initialize(INTERACTION)
                .unwrap_err(),
            InitError::VaultKeyMissing
        );
        assert_eq!(keys.store_calls(), 0);
        assert!(store.pending().is_none());
    }

    #[test]
    fn healthy_live_vault_takes_precedence_and_preserves_conflicting_pending_state() {
        let vault_id = VaultId::from_bytes([1; 16]);
        let key_id = KeyId::from_bytes([2; 16]);
        let key = MasterKey::from_bytes([3; 32]);
        let live = seal_vault(&Vault::empty(), vault_id, key_id, &key).unwrap();
        let pending = b"reserved conflicting pending state".to_vec();
        let keys = MemoryKeyProvider::new();
        keys.insert(key_id, &key);
        let store = MemoryVaultStore::new();
        store.set_live(live.to_vec());
        store.set_pending(pending.clone());

        assert_eq!(
            Initializer::new(&keys, &store)
                .initialize(INTERACTION)
                .unwrap(),
            InitOutcome::AlreadyInitialized {
                vault_id,
                key_id,
                revision: 0,
            }
        );
        assert_eq!(store.pending(), Some(pending));
        assert_eq!(keys.store_calls(), 0);
    }

    #[test]
    fn indeterminate_promotion_is_resolved_when_the_new_live_vault_authenticates() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        store.fail_next_promotion(PromotionFault::IndeterminateAfterCommit);

        assert!(matches!(
            Initializer::new(&keys, &store)
                .initialize(INTERACTION)
                .unwrap(),
            InitOutcome::Created { .. }
        ));
        assert!(store.live().is_some());
        assert!(store.pending().is_none());
    }

    #[test]
    fn unresolved_indeterminate_promotion_returns_exit_fifteen() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        store.fail_next_promotion(PromotionFault::IndeterminateBeforeCommit);

        let error = Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap_err();
        assert_eq!(error, InitError::CommitOutcomeIndeterminate);
        assert_eq!(error.exit_code(), 15);
        assert!(store.live().is_none());
        assert!(store.pending().is_some());
        assert_eq!(keys.key_count(), 1);
    }

    #[test]
    fn repeated_random_key_id_collisions_leave_no_pending_envelope() {
        let keys = MemoryKeyProvider::new();
        keys.always_fail_store(KeyProviderErrorKind::AlreadyExists);
        let store = MemoryVaultStore::new();

        let error = Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap_err();
        assert_eq!(error.exit_code(), 11);
        assert_eq!(keys.store_calls(), MAX_ID_COLLISION_RETRIES);
        assert!(store.live().is_none());
        assert!(store.pending().is_none());
    }

    #[test]
    fn store_errors_keep_their_portable_exit_mapping() {
        let error = InitError::Store(VaultStoreError::new(VaultStoreErrorKind::UnsafePath));
        assert_eq!(error.exit_code(), 13);
        assert!(!error.to_string().contains("secret"));
    }
}
