#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use zeroize::Zeroizing;

use crate::{
    DomainError, EnvelopeError, EnvironmentName, KeyId, MasterKey, Mutation, ProfileName,
    SecretValue, Vault, VaultId,
    domain::{ImportPlan, ProfileSnapshot},
    inspect_envelope,
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

/// One authenticated names-only vault inspection for `status`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VaultInspection {
    pub(crate) revision: u64,
    pub(crate) profiles: Vec<ProfileInspection>,
}

/// Value- and name-free authenticated readiness metadata for `doctor`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VaultReadiness {
    pub(crate) revision: u64,
}

/// Safe metadata confirming an exact authenticated encrypted backup copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BackupReceipt {
    pub(crate) revision: u64,
}

/// Portable, value-free failure categories for a user-selected backup path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackupDestinationError {
    UnsafePath,
    UnsupportedStorage,
    AlreadyExists,
    PermissionDenied,
    IoFailure,
    OutcomeIndeterminate,
}

impl BackupDestinationError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::UnsafePath | Self::UnsupportedStorage | Self::PermissionDenied => 13,
            Self::AlreadyExists => 14,
            Self::OutcomeIndeterminate => 15,
            Self::IoFailure => 1,
        }
    }
}

impl fmt::Display for BackupDestinationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafePath => "the backup destination path is unsafe",
            Self::UnsupportedStorage => "the backup destination is not on supported local APFS storage",
            Self::AlreadyExists => "the backup destination already exists; it was not replaced",
            Self::PermissionDenied => "permission to create the encrypted backup was denied",
            Self::IoFailure => "the encrypted backup could not be created",
            Self::OutcomeIndeterminate => {
                "the backup creation outcome is indeterminate; inspect the destination before retrying"
            }
        })
    }
}

impl Error for BackupDestinationError {}

/// A value-free authenticated backup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackupOperationError {
    Profile(ProfileOperationError),
    Destination(BackupDestinationError),
}

impl BackupOperationError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::Profile(error) => error.exit_code(),
            Self::Destination(error) => error.exit_code(),
        }
    }
}

impl fmt::Display for BackupOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(error) => error.fmt(formatter),
            Self::Destination(error) => error.fmt(formatter),
        }
    }
}

impl Error for BackupOperationError {}

impl From<ProfileOperationError> for BackupOperationError {
    fn from(error: ProfileOperationError) -> Self {
        Self::Profile(error)
    }
}

impl From<BackupDestinationError> for BackupOperationError {
    fn from(error: BackupDestinationError) -> Self {
        Self::Destination(error)
    }
}

impl From<VaultStoreError> for BackupOperationError {
    fn from(error: VaultStoreError) -> Self {
        Self::Profile(error.into())
    }
}

/// Safe metadata confirming an authenticated vault mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MutationReceipt {
    pub(crate) revision: u64,
}

/// Safe metadata confirming whether `set` created or updated a variable name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SetReceipt {
    pub(crate) revision: u64,
    pub(crate) mutation: Mutation,
}

/// Safe metadata confirming one atomic additive import.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ImportReceipt {
    pub(crate) plan: ImportPlan,
}

/// A value-free import failure. Collision details contain names only.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ImportOperationError {
    Profile(ProfileOperationError),
    Collisions(Vec<EnvironmentName>),
}

impl ImportOperationError {
    pub(crate) const fn exit_code(&self) -> u8 {
        match self {
            Self::Profile(error) => error.exit_code(),
            Self::Collisions(_) => 14,
        }
    }
}

impl fmt::Display for ImportOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(error) => error.fmt(formatter),
            Self::Collisions(_) => formatter.write_str(
                "import collides with existing variables; use --replace-existing to authorize replacement",
            ),
        }
    }
}

impl Error for ImportOperationError {}

impl From<ProfileOperationError> for ImportOperationError {
    fn from(error: ProfileOperationError) -> Self {
        Self::Profile(error)
    }
}

impl From<DomainError> for ImportOperationError {
    fn from(error: DomainError) -> Self {
        Self::Profile(error.into())
    }
}

impl From<EnvelopeError> for ImportOperationError {
    fn from(error: EnvelopeError) -> Self {
        Self::Profile(error.into())
    }
}

impl From<VaultStoreError> for ImportOperationError {
    fn from(error: VaultStoreError) -> Self {
        Self::Profile(error.into())
    }
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
        self.mutate(interaction, move |vault| {
            vault.create_profile(profile)?;
            Ok(())
        })
        .map(|(receipt, ())| receipt)
    }

    pub(crate) fn rename(
        &self,
        old: &ProfileName,
        new: ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<MutationReceipt, ProfileOperationError> {
        self.mutate(interaction, move |vault| {
            vault.rename_profile(old, new)?;
            Ok(())
        })
        .map(|(receipt, ())| receipt)
    }

    pub(crate) fn preflight_rename(
        &self,
        old: &ProfileName,
        new: &ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<(), ProfileOperationError> {
        self.store.shared_read(|read| {
            let (opened, _key) = self.open_current(read, interaction)?;
            if !opened.vault.contains_profile(old) {
                return Err(DomainError::ProfileNotFound.into());
            }
            if opened.vault.contains_profile(new) {
                return Err(DomainError::ProfileAlreadyExists.into());
            }
            Ok(())
        })
    }

    pub(crate) fn delete(
        &self,
        profile: &ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<MutationReceipt, ProfileOperationError> {
        self.mutate(interaction, move |vault| {
            vault.delete_profile(profile)?;
            Ok(())
        })
        .map(|(receipt, ())| receipt)
    }

    pub(crate) fn preflight_set(
        &self,
        profile: &ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<(), ProfileOperationError> {
        self.store.shared_read(|read| {
            let (opened, _key) = self.open_current(read, interaction)?;
            if !opened.vault.contains_profile(profile) {
                return Err(DomainError::ProfileNotFound.into());
            }
            Ok(())
        })
    }

    pub(crate) fn preflight_import(
        &self,
        profile: &ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<(), ProfileOperationError> {
        self.preflight_set(profile, interaction)
    }

    pub(crate) fn preview_import(
        &self,
        profile: &ProfileName,
        imported: &std::collections::BTreeMap<EnvironmentName, SecretValue>,
        interaction: InteractionPolicy,
    ) -> Result<ImportPlan, ImportOperationError> {
        self.store.shared_read(|read| {
            let (opened, _key) = self.open_current(read, interaction)?;
            opened
                .vault
                .plan_import(profile, imported)
                .map_err(Into::into)
        })
    }

    pub(crate) fn import(
        &self,
        profile: &ProfileName,
        imported: std::collections::BTreeMap<EnvironmentName, SecretValue>,
        replace_existing: bool,
        interaction: InteractionPolicy,
    ) -> Result<ImportReceipt, ImportOperationError> {
        self.store.exclusive_transaction(|transaction| {
            Self::ensure_no_rebuild_pending(transaction)?;
            let (mut opened, key) = self.open_current(transaction, interaction)?;
            let preview = opened.vault.plan_import(profile, &imported)?;
            if !replace_existing && !preview.collisions.is_empty() {
                return Err(ImportOperationError::Collisions(preview.collisions));
            }
            if imported.is_empty() {
                return Ok(ImportReceipt { plan: preview });
            }

            let plan = opened.vault.apply_import(profile, imported)?;
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
            Ok(ImportReceipt { plan })
        })
    }

    pub(crate) fn set(
        &self,
        profile: &ProfileName,
        name: EnvironmentName,
        value: SecretValue,
        interaction: InteractionPolicy,
    ) -> Result<SetReceipt, ProfileOperationError> {
        self.mutate(interaction, move |vault| vault.set(profile, name, value))
            .map(|(receipt, mutation)| SetReceipt {
                revision: receipt.revision,
                mutation,
            })
    }

    pub(crate) fn remove(
        &self,
        profile: &ProfileName,
        name: &EnvironmentName,
        interaction: InteractionPolicy,
    ) -> Result<MutationReceipt, ProfileOperationError> {
        self.mutate(interaction, move |vault| {
            vault.remove(profile, name)?;
            Ok(())
        })
        .map(|(receipt, ())| receipt)
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

    pub(crate) fn inspect_all(
        &self,
        interaction: InteractionPolicy,
    ) -> Result<VaultInspection, ProfileOperationError> {
        self.store.shared_read(|read| {
            let (opened, _key) = self.open_current(read, interaction)?;
            let profiles = opened
                .vault
                .profile_names()
                .map(|profile| {
                    let variables = opened.vault.variable_names(profile)?.cloned().collect();
                    Ok(ProfileInspection {
                        profile: profile.clone(),
                        variables,
                    })
                })
                .collect::<Result<_, DomainError>>()?;
            Ok(VaultInspection {
                revision: opened.vault.revision(),
                profiles,
            })
        })
    }

    pub(crate) fn readiness(
        &self,
        interaction: InteractionPolicy,
    ) -> Result<VaultReadiness, ProfileOperationError> {
        self.store.shared_read(|read| {
            let (opened, _key) = self.open_current(read, interaction)?;
            Ok(VaultReadiness {
                revision: opened.vault.revision(),
            })
        })
    }

    pub(crate) fn backup_to(
        &self,
        interaction: InteractionPolicy,
        destination: impl FnOnce(&[u8]) -> Result<(), BackupDestinationError>,
    ) -> Result<BackupReceipt, BackupOperationError> {
        self.store.shared_read(|read| {
            let (opened, key, envelope) = self.open_current_with_envelope(read, interaction)?;
            let receipt = BackupReceipt {
                revision: opened.vault.revision(),
            };
            // The destination needs only the already-authenticated ciphertext.
            // Drop decrypted values and key material before filesystem I/O while
            // retaining the shared vault lock for the exact snapshot copy.
            drop(opened);
            drop(key);
            destination(&envelope)?;
            Ok(receipt)
        })
    }

    pub(crate) fn snapshot(
        &self,
        profile: &ProfileName,
        interaction: InteractionPolicy,
    ) -> Result<ProfileSnapshot, ProfileOperationError> {
        self.store.shared_read(|read| {
            let (opened, _key) = self.open_current(read, interaction)?;
            opened
                .vault
                .into_profile_snapshot(profile)
                .map_err(Into::into)
        })
    }

    fn mutate<R>(
        &self,
        interaction: InteractionPolicy,
        operation: impl FnOnce(&mut Vault) -> Result<R, DomainError>,
    ) -> Result<(MutationReceipt, R), ProfileOperationError> {
        self.store.exclusive_transaction(|transaction| {
            Self::ensure_no_rebuild_pending(transaction)?;
            let (mut opened, key) = self.open_current(transaction, interaction)?;
            let result = operation(&mut opened.vault)?;
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
            Ok((
                MutationReceipt {
                    revision: expected_revision,
                },
                result,
            ))
        })
    }

    fn open_current(
        &self,
        read: &mut dyn VaultRead,
        interaction: InteractionPolicy,
    ) -> Result<(crate::OpenedVault, MasterKey), ProfileOperationError> {
        let (opened, key, _envelope) = self.open_current_with_envelope(read, interaction)?;
        Ok((opened, key))
    }

    fn ensure_no_rebuild_pending(read: &mut dyn VaultRead) -> Result<(), ProfileOperationError> {
        if read.read_rebuild_pending()?.is_some() {
            return Err(VaultStoreError::new(VaultStoreErrorKind::Conflict).into());
        }
        Ok(())
    }

    fn open_current_with_envelope(
        &self,
        read: &mut dyn VaultRead,
        interaction: InteractionPolicy,
    ) -> Result<(crate::OpenedVault, MasterKey, Zeroizing<Vec<u8>>), ProfileOperationError> {
        let envelope = read
            .read_live()?
            .ok_or(ProfileOperationError::NotInitialized)?;
        let metadata = inspect_envelope(&envelope)?;
        let key = self
            .keys
            .load(&metadata.key_id, interaction)
            .map_err(ProfileOperationError::from_key_provider)?;
        let opened = open_envelope(&envelope, &key)?;
        Ok((opened, key, envelope))
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
    fn sets_updates_and_removes_exact_secret_values() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        let dev = profile("dev");
        let variable = EnvironmentName::new("API_TOKEN").unwrap();
        operations.create(dev.clone(), INTERACTION).unwrap();
        operations.preflight_set(&dev, INTERACTION).unwrap();

        let created = operations
            .set(
                &dev,
                variable.clone(),
                SecretValue::new(b"  first\n\n".to_vec()).unwrap(),
                INTERACTION,
            )
            .unwrap();
        assert_eq!(
            created,
            SetReceipt {
                revision: 2,
                mutation: Mutation::Created,
            }
        );
        let updated = operations
            .set(
                &dev,
                variable.clone(),
                SecretValue::from_string("ü $() `updated`\t".to_owned()).unwrap(),
                INTERACTION,
            )
            .unwrap();
        assert_eq!(updated.revision, 3);
        assert_eq!(updated.mutation, Mutation::Updated);

        let live = store.live().unwrap();
        let metadata = inspect_envelope(&live).unwrap();
        let key = keys.load(&metadata.key_id, INTERACTION).unwrap();
        let opened = open_envelope(&live, &key).unwrap();
        assert!(
            opened.vault.secret(&dev, &variable) == Some("ü $() `updated`\t".as_bytes()),
            "updated secret bytes mismatch"
        );

        assert_eq!(
            operations
                .remove(&dev, &variable, INTERACTION)
                .unwrap()
                .revision,
            4
        );
        assert!(
            operations
                .inspect(&dev, INTERACTION)
                .unwrap()
                .variables
                .is_empty()
        );
    }

    #[test]
    fn authenticated_snapshot_consumes_only_the_selected_profile_without_rewriting() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        let work = profile("work");
        let other = profile("other");
        operations.create(work.clone(), INTERACTION).unwrap();
        operations.create(other.clone(), INTERACTION).unwrap();
        operations
            .set(
                &work,
                EnvironmentName::new("TOKEN").unwrap(),
                SecretValue::from_string("CANARY-selected".to_owned()).unwrap(),
                INTERACTION,
            )
            .unwrap();
        operations
            .set(
                &other,
                EnvironmentName::new("OTHER_TOKEN").unwrap(),
                SecretValue::from_string("CANARY-unselected".to_owned()).unwrap(),
                INTERACTION,
            )
            .unwrap();
        let before = store.live().unwrap();

        let snapshot = operations.snapshot(&work, INTERACTION).unwrap();
        assert_eq!(snapshot.name(), &work);
        let variables = snapshot.variables();
        assert_eq!(variables.len(), 1);
        assert_eq!(variables[0].0, EnvironmentName::new("TOKEN").unwrap());
        assert!(
            variables[0].1.expose() == b"CANARY-selected",
            "snapshot secret bytes mismatch"
        );
        assert_eq!(store.live().unwrap(), before);
    }

    #[test]
    fn diagnostic_reads_expose_only_their_intended_metadata() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        let dev = profile("dev");
        operations.create(dev.clone(), INTERACTION).unwrap();
        operations
            .set(
                &dev,
                EnvironmentName::new("API_TOKEN").unwrap(),
                SecretValue::from_string("CANARY-diagnostic-secret".to_owned()).unwrap(),
                INTERACTION,
            )
            .unwrap();
        let before = store.live().unwrap();

        let inspection = operations.inspect_all(INTERACTION).unwrap();
        assert_eq!(inspection.revision, 2);
        assert_eq!(inspection.profiles.len(), 1);
        assert_eq!(inspection.profiles[0].profile, dev);
        assert_eq!(
            inspection.profiles[0].variables,
            vec![EnvironmentName::new("API_TOKEN").unwrap()]
        );
        assert!(!format!("{inspection:?}").contains("CANARY-diagnostic-secret"));

        let readiness = operations.readiness(INTERACTION).unwrap();
        assert_eq!(readiness, VaultReadiness { revision: 2 });
        let rendered = format!("{readiness:?}");
        assert!(!rendered.contains("dev"));
        assert!(!rendered.contains("API_TOKEN"));
        assert!(!rendered.contains("CANARY-diagnostic-secret"));
        assert_eq!(store.live().unwrap(), before);
    }

    #[test]
    fn diagnostic_readiness_preserves_frozen_failure_categories() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        keys.fail_next_load(KeyProviderErrorKind::NotFound);
        assert_eq!(
            operations.readiness(INTERACTION).unwrap_err(),
            ProfileOperationError::VaultKeyMissing
        );

        store.set_live(b"not-an-envelope".to_vec());
        assert!(matches!(
            operations.readiness(INTERACTION),
            Err(ProfileOperationError::Vault(_))
        ));
    }

    #[test]
    fn set_preflight_rejects_missing_profile_before_mutation() {
        let (keys, store) = initialized();
        let before = store.live().unwrap();
        let error = ProfileOperations::new(&keys, &store)
            .preflight_set(&profile("missing"), INTERACTION)
            .unwrap_err();
        assert_eq!(
            error,
            ProfileOperationError::Domain(DomainError::ProfileNotFound)
        );
        assert_eq!(store.live().unwrap(), before);
    }

    #[test]
    fn rename_preflight_authenticates_both_names_without_rewriting() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        let work = profile("work");
        let existing = profile("existing");
        operations.create(work.clone(), INTERACTION).unwrap();
        operations.create(existing.clone(), INTERACTION).unwrap();
        let before = store.live().unwrap();

        operations
            .preflight_rename(&work, &profile("new"), INTERACTION)
            .unwrap();
        assert_eq!(
            operations
                .preflight_rename(&profile("missing"), &profile("new"), INTERACTION)
                .unwrap_err(),
            ProfileOperationError::Domain(DomainError::ProfileNotFound)
        );
        assert_eq!(
            operations
                .preflight_rename(&work, &existing, INTERACTION)
                .unwrap_err(),
            ProfileOperationError::Domain(DomainError::ProfileAlreadyExists)
        );
        assert_eq!(store.live().unwrap(), before);
    }

    #[test]
    fn failed_set_commit_never_places_canary_in_live_state() {
        let (keys, store) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        let dev = profile("dev");
        operations.create(dev.clone(), INTERACTION).unwrap();
        let before = store.live().unwrap();
        store.fail_next_replacement(ReplacementFault::NotCommitted);

        let error = operations
            .set(
                &dev,
                EnvironmentName::new("TOKEN").unwrap(),
                SecretValue::from_string("CANARY-not-committed".to_owned()).unwrap(),
                INTERACTION,
            )
            .unwrap_err();
        assert_eq!(error, ProfileOperationError::CommitNotCompleted);
        assert_eq!(store.live().unwrap(), before);
        assert!(
            !before.windows(6).any(|window| window == b"CANARY"),
            "failed mutation exposed secret bytes"
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
        assert!(
            !format!("{inspection:?}").contains("CANARY-very-secret"),
            "profile inspection exposed secret bytes"
        );
        let committed = store.live().unwrap();
        assert!(
            !committed.windows(6).any(|window| window == b"CANARY"),
            "committed envelope exposed secret bytes"
        );
        let opened = open_envelope(&committed, &key).unwrap();
        assert!(
            opened.vault.secret(&dev, &variable) == Some(b"CANARY-very-secret".as_slice()),
            "preserved secret bytes mismatch"
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
