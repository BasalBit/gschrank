#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use crate::{
    EnvironmentName, ProfileName, SecretValue,
    key_provider::{InteractionPolicy, KeyProvider},
    profiles::{ProfileOperationError, ProfileOperations, SetReceipt},
    secret_input::SecretInputError,
    vault_store::VaultStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SetCommandError {
    Vault(ProfileOperationError),
    Input(SecretInputError),
}

impl SetCommandError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::Vault(error) => error.exit_code(),
            Self::Input(error) => error.exit_code(),
        }
    }
}

impl fmt::Display for SetCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault(error) => fmt::Display::fmt(error, formatter),
            Self::Input(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for SetCommandError {}

/// Validates authenticated destination state before invoking the secret source,
/// then revalidates and atomically commits the supplied value.
pub(crate) fn execute_set<K, S>(
    operations: &ProfileOperations<'_, K, S>,
    profile: &ProfileName,
    variable: EnvironmentName,
    interaction: InteractionPolicy,
    acquire_secret: impl FnOnce() -> Result<SecretValue, SecretInputError>,
) -> Result<SetReceipt, SetCommandError>
where
    K: KeyProvider,
    S: VaultStore,
{
    operations
        .preflight_set(profile, interaction)
        .map_err(SetCommandError::Vault)?;
    let value = acquire_secret().map_err(SetCommandError::Input)?;
    operations
        .set(profile, variable, value, interaction)
        .map_err(SetCommandError::Vault)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::{
        DomainError, Mutation,
        init::Initializer,
        testing::{MemoryKeyProvider, MemoryVaultStore},
    };

    const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;

    fn profile(name: &str) -> ProfileName {
        ProfileName::new(name).unwrap()
    }

    #[test]
    fn invalid_destination_is_rejected_before_secret_acquisition() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let operations = ProfileOperations::new(&keys, &store);
        let acquired = Cell::new(false);

        let error = execute_set(
            &operations,
            &profile("missing"),
            EnvironmentName::new("TOKEN").unwrap(),
            INTERACTION,
            || {
                acquired.set(true);
                SecretValue::from_string("CANARY-must-not-be-read".to_owned())
                    .map_err(SecretInputError::InvalidValue)
            },
        )
        .unwrap_err();

        assert_eq!(
            error,
            SetCommandError::Vault(ProfileOperationError::Domain(DomainError::ProfileNotFound))
        );
        assert!(!acquired.get());
    }

    #[test]
    fn valid_destination_acquires_once_and_commits_metadata_only_outcome() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let operations = ProfileOperations::new(&keys, &store);
        let dev = profile("dev");
        operations.create(dev.clone(), INTERACTION).unwrap();
        let acquired = Cell::new(0_u8);

        let receipt = execute_set(
            &operations,
            &dev,
            EnvironmentName::new("TOKEN").unwrap(),
            INTERACTION,
            || {
                acquired.set(acquired.get() + 1);
                SecretValue::from_string("CANARY-committed".to_owned())
                    .map_err(SecretInputError::InvalidValue)
            },
        )
        .unwrap();

        assert_eq!(acquired.get(), 1);
        assert_eq!(receipt.mutation, Mutation::Created);
        assert!(
            !format!("{receipt:?}").contains("CANARY"),
            "set receipt exposed secret bytes"
        );
    }

    #[test]
    fn input_failure_after_preflight_preserves_the_authenticated_vault() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let operations = ProfileOperations::new(&keys, &store);
        let dev = profile("dev");
        operations.create(dev.clone(), INTERACTION).unwrap();
        let before = store.live().unwrap();

        let error = execute_set(
            &operations,
            &dev,
            EnvironmentName::new("TOKEN").unwrap(),
            INTERACTION,
            || Err(SecretInputError::IoFailure),
        )
        .unwrap_err();

        assert_eq!(error, SetCommandError::Input(SecretInputError::IoFailure));
        assert_eq!(error.exit_code(), 1);
        assert_eq!(store.live().unwrap(), before);
    }
}
