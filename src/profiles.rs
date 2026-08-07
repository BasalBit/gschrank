#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use crate::{
    DomainError, EnvelopeError, KeyId, MasterKey, ProfileName, Vault, VaultId, inspect_envelope,
    key_provider::{InteractionPolicy, KeyProvider, KeyProviderError, KeyProviderErrorKind},
    open_envelope, seal_vault,
    vault_store::{
        CommitOutcome, VaultRead, VaultStore, VaultStoreError, VaultStoreErrorKind,
        VaultTransaction,
    },
};

/// Safe names-only information returned by `profile inspect`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ProfileInspection {
    pub(crate) profile: ProfileName,
    pub(crate) variables: Vec<crate::EnvironmentName>,
}

/// Safe metadata confirming an authenticated vault mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MutationReceipt {
    pub(crate) revision: u64,
}

/// A value-free authenticated profile-operation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileOperationError {
    NotInitialized,
    SecureStore(KeyProviderError),
    VaultKeyMissing,
    InvalidKeyMaterial,
    Vault(EnvelopeError),
    Domain(DomainError),
    Store(VaultStoreError),
    CommitNotCompleted,
    CommitOutcomeIndeterminate,
}

impl ProfileOperationError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::NotInitialized => 10,
            Self::SecureStore(_) => 11,
            Self::VaultKeyMissing | Self::InvalidKeyMaterial | Self::Vault(_) => 12,
            Self::Domain(error) => match error {
                DomainError::InvalidProfileName
                | DomainError::InvalidEnvironmentName
                | DomainError::ReservedEnvironmentName
                | DomainError::InvalidValue => 2,
                DomainError::ProfileAlreadyExists
                | DomainError::ProfileNotFound
                | DomainError::VariableNotFound
                | DomainError::ProfileLimitExceeded
                | DomainError::VariableLimitExceeded
                | DomainError::ValueLimitExceeded
                | DomainError::ProfileSizeLimitExceeded
                | DomainError::RevisionExhausted => 14,
            },
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

impl From<DomainError> for ProfileOperationError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

impl From<EnvelopeError> for ProfileOperationError {
    fn from(error: EnvelopeError) -> Self {
        Self::Vault(error)
    }
}

impl From<VaultStoreError> for ProfileOperationError {
    fn from(error: VaultStoreError) -> Self {
        match error.kind() {
            VaultStoreErrorKind::MissingState => Self::NotInitialized,
            VaultStoreErrorKind::OutcomeIndeterminate => Self::CommitOutcomeIndeterminate,
            VaultStoreErrorKind::UnsafePath
            | VaultStoreErrorKind::PermissionDenied
            | VaultStoreErrorKind::LockFailure
            | VaultStoreErrorKind::UnsupportedStorage
            | VaultStoreErrorKind::Conflict
            | VaultStoreErrorKind::IoFailure => Self::Store(error),
        }
    }
}

impl fmt::Display for ProfileOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => formatter.write_str("Gschrank is not initialized"),
            Self::SecureStore(_) => formatter.write_str("secure-store access failed"),
            Self::VaultKeyMissing => formatter.write_str("the vault's secure-store key is missing"),
            Self::InvalidKeyMaterial => {
                formatter.write_str("the vault's secure-store key is invalid")
            }
            Self::Vault(_) => formatter.write_str("the encrypted vault is unreadable"),
            Self::Domain(error) => error.fmt(formatter),
            Self::Store(_) => formatter.write_str("the local vault store failed"),
            Self::CommitNotCompleted => formatter.write_str("vault mutation did not commit"),
            Self::CommitOutcomeIndeterminate => {
                formatter.write_str("vault mutation outcome is indeterminate")
            }
        }
    }
}

impl Error for ProfileOperationError {}

/// Authenticated names-only profile operations over one locked vault-store seam.
pub(crate) struct ProfileOperations<'dependencies, K, S> {
    keys: &'dependencies K,
    store: &'dependencies S,
}

impl<'dependencies, K, S> ProfileOperations<'dependencies, K, S>
where
    K: KeyProvider,
    S: VaultStore,
{
    pub(crate) const fn new(keys: &'dependencies K, store: &'dependencies S) -> Self {
        Self { keys, store }
    }

    pub(crate) fn create(
        &self,
        profile: ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<MutationReceipt, ProfileOperationError> {
        self.mutate(interaction, move |vault| vault.create_profile(profile))
    }

    pub(crate) fn rename(
        &self,
        old: &ProfileName,
        new: ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<MutationReceipt, ProfileOperationError> {
        self.mutate(interaction, move |vault| vault.rename_profile(old, new))
    }

    pub(crate) fn delete(
        &self,
        profile: &ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<MutationReceipt, ProfileOperationError> {
        self.mutate(interaction, move |vault| vault.delete_profile(profile))
    }

    pub(crate) fn list(
        &self,
        interaction: InteractionPolicy,
    ) -> Result<Vec<ProfileName>, ProfileOperationError> {
        self.store.shared_read(|read| {
            let (opened, _key) = self.open_current(read, interaction)?;
            Ok(opened.vault.profile_names().cloned().collect())
        })
    }

    pub(crate) fn inspect(
        &self,
        profile: &ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<ProfileInspection, ProfileOperationError> {
        self.store.shared_read(|read| {
            let (opened, _key) = self.open_current(read, interaction)?;
            let variables = opened.vault.variable_names(profile)?.cloned().collect();
            Ok(ProfileInspection {
                profile: profile.clone(),
                variables,
            })
        })
    }

    fn mutate(
        &self,
        interaction: InteractionPolicy,
        operation: impl FnOnce(&mut Vault) -> Result<(), DomainError>,
    ) -> Result<MutationReceipt, ProfileOperationError> {
        self.store.exclusive_transaction(|transaction| {
            let (mut opened, key) = self.open_current(transaction, interaction)?;
            operation(&mut opened.vault)?;
            let expected_revision = opened.vault.revision();
            let replacement = seal_vault(&opened.vault, opened.vault_id, opened.key_id, &key)?;
            let outcome = transaction.replace_live(&replacement)?;
            Self::verify_commit(
                transaction,
                outcome,
                &key,
                opened.vault_id,
                opened.key_id,
                expected_revision,
            )?;
            Ok(MutationReceipt {
                revision: expected_revision,
            })
        })
    }

    fn open_current(
        &self,
        read: &mut dyn VaultRead,
        interaction: InteractionPolicy,
    ) -> Result<(crate::OpenedVault, MasterKey), ProfileOperationError> {
        let envelope = read
            .read_live()?
            .ok_or(ProfileOperationError::NotInitialized)?;
        let metadata = inspect_envelope(&envelope)?;
        let key = self
            .keys
            .load(&metadata.key_id, interaction)
            .map_err(ProfileOperationError::from_key_provider)?;
        let opened = open_envelope(&envelope, &key)?;
        Ok((opened, key))
    }

    fn verify_commit(
        transaction: &mut dyn VaultTransaction,
        outcome: CommitOutcome,
        key: &MasterKey,
        expected_vault_id: VaultId,
        expected_key_id: KeyId,
        expected_revision: u64,
    ) -> Result<(), ProfileOperationError> {
        if outcome == CommitOutcome::NotCommitted {
            return Err(ProfileOperationError::CommitNotCompleted);
        }

        let committed = transaction.read_live().and_then(|envelope| {
            envelope.ok_or_else(|| VaultStoreError::new(VaultStoreErrorKind::MissingState))
        });
        let opened = match (outcome, committed) {
            (CommitOutcome::Committed, Ok(envelope)) => open_envelope(&envelope, key)?,
            (CommitOutcome::Indeterminate, Ok(envelope)) => open_envelope(&envelope, key)
                .map_err(|_| ProfileOperationError::CommitOutcomeIndeterminate)?,
            (CommitOutcome::Committed | CommitOutcome::Indeterminate, Err(_)) => {
                return Err(ProfileOperationError::CommitOutcomeIndeterminate);
            }
            (CommitOutcome::NotCommitted, _) => unreachable!("handled above"),
        };

        if opened.vault_id != expected_vault_id
            || opened.key_id != expected_key_id
            || opened.vault.revision() != expected_revision
        {
            return Err(ProfileOperationError::CommitOutcomeIndeterminate);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EnvironmentName, SecretValue,
        init::Initializer,
        testing::{MemoryKeyProvider, MemoryVaultStore, ReplacementFault},
    };

    const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;

    fn profile(name: &str) -> ProfileName {
        ProfileName::new(name).unwrap()
    }

    fn initialized() -> (MemoryKeyProvider, MemoryVaultStore) {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        (keys, store)
    }

    #[test]
    fn performs_authenticated_profile_crud_with_monotonic_revisions() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);

        assert_eq!(
            operations
                .create(profile("work"), INTERACTION)
                .unwrap()
                .revision,
            1
        );
        assert_eq!(
            operations
                .create(profile("dev"), INTERACTION)
                .unwrap()
                .revision,
            2
        );
        assert_eq!(
            operations.list(INTERACTION).unwrap(),
            vec![profile("dev"), profile("work")]
        );
        assert_eq!(
            operations.inspect(&profile("dev"), INTERACTION).unwrap(),
            ProfileInspection {
                profile: profile("dev"),
                variables: Vec::new(),
            }
        );
        assert_eq!(
            operations
                .rename(&profile("dev"), profile("local"), INTERACTION)
                .unwrap()
                .revision,
            3
        );
        assert_eq!(
            operations
                .delete(&profile("work"), INTERACTION)
                .unwrap()
                .revision,
            4
        );
        assert_eq!(
            operations.list(INTERACTION).unwrap(),
            vec![profile("local")]
        );
    }

    #[test]
    fn domain_failure_does_not_rewrite_the_envelope() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        operations.create(profile("dev"), INTERACTION).unwrap();
        let before = store.live().unwrap();

        let error = operations.create(profile("dev"), INTERACTION).unwrap_err();
        assert_eq!(
            error,
            ProfileOperationError::Domain(DomainError::ProfileAlreadyExists)
        );
        assert_eq!(error.exit_code(), 14);
        assert_eq!(store.live().unwrap(), before);
    }

    #[test]
    fn secure_store_failure_preserves_the_live_envelope() {
        let (keys, store) = initialized();
        let before = store.live().unwrap();
        keys.fail_next_load(KeyProviderErrorKind::InteractionRequired);

        let error = ProfileOperations::new(&keys, &store)
            .create(profile("dev"), INTERACTION)
            .unwrap_err();
        assert!(matches!(error, ProfileOperationError::SecureStore(_)));
        assert_eq!(error.exit_code(), 11);
        assert_eq!(store.live().unwrap(), before);
    }

    #[test]
    fn indeterminate_replacement_resolves_only_when_new_revision_is_live() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        store.fail_next_replacement(ReplacementFault::IndeterminateAfterCommit);
        assert_eq!(
            operations
                .create(profile("dev"), INTERACTION)
                .unwrap()
                .revision,
            1
        );

        store.fail_next_replacement(ReplacementFault::IndeterminateBeforeCommit);
        let error = operations.create(profile("work"), INTERACTION).unwrap_err();
        assert_eq!(error, ProfileOperationError::CommitOutcomeIndeterminate);
        assert_eq!(error.exit_code(), 15);
        assert_eq!(operations.list(INTERACTION).unwrap(), vec![profile("dev")]);
    }

    #[test]
    fn noncommitted_replacement_preserves_the_previous_envelope() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        let before = store.live().unwrap();
        store.fail_next_replacement(ReplacementFault::NotCommitted);

        assert_eq!(
            operations.create(profile("dev"), INTERACTION).unwrap_err(),
            ProfileOperationError::CommitNotCompleted
        );
        assert_eq!(store.live().unwrap(), before);
    }

    #[test]
    fn profile_mutation_preserves_existing_secret_bytes_without_exposing_them() {
        let vault_id = VaultId::from_bytes([1; 16]);
        let key_id = KeyId::from_bytes([2; 16]);
        let key = MasterKey::from_bytes([3; 32]);
        let mut vault = Vault::empty();
        let dev = profile("dev");
        let variable = EnvironmentName::new("TOKEN").unwrap();
        vault.create_profile(dev.clone()).unwrap();
        vault
            .set(
                &dev,
                variable.clone(),
                SecretValue::from_string("CANARY-very-secret".to_owned()).unwrap(),
            )
            .unwrap();
        let live = seal_vault(&vault, vault_id, key_id, &key).unwrap();
        let keys = MemoryKeyProvider::new();
        keys.insert(key_id, &key);
        let store = MemoryVaultStore::new();
        store.set_live(live.to_vec());

        let operations = ProfileOperations::new(&keys, &store);
        operations.create(profile("work"), INTERACTION).unwrap();
        let inspection = operations.inspect(&dev, INTERACTION).unwrap();
        assert_eq!(inspection.variables, vec![variable.clone()]);
        assert!(!format!("{inspection:?}").contains("CANARY-very-secret"));
        let committed = store.live().unwrap();
        assert!(!committed.windows(6).any(|window| window == b"CANARY"));
        let opened = open_envelope(&committed, &key).unwrap();
        assert_eq!(
            opened.vault.secret(&dev, &variable),
            Some(b"CANARY-very-secret".as_slice())
        );
    }

    #[test]
    fn absent_live_vault_reports_not_initialized_without_key_access() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        let error = ProfileOperations::new(&keys, &store)
            .list(INTERACTION)
            .unwrap_err();
        assert_eq!(error, ProfileOperationError::NotInitialized);
        assert_eq!(error.exit_code(), 10);
    }
}
