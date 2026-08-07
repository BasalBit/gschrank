#![forbid(unsafe_code)]

use std::{error::Error, fmt, io::Read};

use crate::{
    ProfileName,
    domain::ImportPlan,
    dotenv::{DotenvError, read_dotenv},
    key_provider::{InteractionPolicy, KeyProvider},
    profiles::{ImportOperationError, ImportReceipt, ProfileOperationError, ProfileOperations},
    vault_store::VaultStore,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImportOptions {
    pub(crate) dry_run: bool,
    pub(crate) replace_existing: bool,
}

pub(crate) enum ImportOutcome {
    NoVariables,
    DryRun {
        plan: ImportPlan,
        replace_existing: bool,
    },
    Imported(ImportReceipt),
}

/// Authenticates the destination before consuming stdin, then reopens the
/// latest vault state for preview or one atomic additive replacement.
pub(crate) fn execute_import<K, S>(
    operations: &ProfileOperations<'_, K, S>,
    profile: &ProfileName,
    options: ImportOptions,
    interaction: InteractionPolicy,
    stdin_is_terminal: bool,
    reader: impl Read,
) -> Result<ImportOutcome, ImportCommandError>
where
    K: KeyProvider,
    S: VaultStore,
{
    execute_import_with_after_parse(
        operations,
        profile,
        options,
        interaction,
        stdin_is_terminal,
        reader,
        || {},
    )
}

fn execute_import_with_after_parse<K, S>(
    operations: &ProfileOperations<'_, K, S>,
    profile: &ProfileName,
    options: ImportOptions,
    interaction: InteractionPolicy,
    stdin_is_terminal: bool,
    reader: impl Read,
    after_parse: impl FnOnce(),
) -> Result<ImportOutcome, ImportCommandError>
where
    K: KeyProvider,
    S: VaultStore,
{
    if stdin_is_terminal {
        return Err(ImportCommandError::TerminalStdin);
    }
    operations.preflight_import(profile, interaction)?;
    let document = read_dotenv(reader)?;
    after_parse();

    if options.dry_run {
        let plan = operations.preview_import(profile, document.variables(), interaction)?;
        return Ok(ImportOutcome::DryRun {
            plan,
            replace_existing: options.replace_existing,
        });
    }
    if document.is_empty() {
        // Revalidate the latest destination without rewriting or incrementing
        // the logical revision.
        operations.preview_import(profile, document.variables(), interaction)?;
        return Ok(ImportOutcome::NoVariables);
    }
    operations
        .import(
            profile,
            document.into_variables(),
            options.replace_existing,
            interaction,
        )
        .map(ImportOutcome::Imported)
        .map_err(Into::into)
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ImportCommandError {
    TerminalStdin,
    Input(DotenvError),
    Profile(ProfileOperationError),
    Operation(ImportOperationError),
}

impl ImportCommandError {
    pub(crate) const fn exit_code(&self) -> u8 {
        match self {
            Self::TerminalStdin => 2,
            Self::Input(error) => error.exit_code(),
            Self::Profile(error) => error.exit_code(),
            Self::Operation(error) => error.exit_code(),
        }
    }
}

impl fmt::Display for ImportCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TerminalStdin => formatter.write_str(
                "dotenv import requires redirected or piped standard input; it refuses terminal stdin",
            ),
            Self::Input(error) => error.fmt(formatter),
            Self::Profile(error) => error.fmt(formatter),
            Self::Operation(error) => error.fmt(formatter),
        }
    }
}

impl Error for ImportCommandError {}

impl From<DotenvError> for ImportCommandError {
    fn from(error: DotenvError) -> Self {
        Self::Input(error)
    }
}

impl From<ProfileOperationError> for ImportCommandError {
    fn from(error: ProfileOperationError) -> Self {
        Self::Profile(error)
    }
}

impl From<ImportOperationError> for ImportCommandError {
    fn from(error: ImportOperationError) -> Self {
        Self::Operation(error)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io, io::Cursor};

    use super::*;
    use crate::{
        EnvironmentName, SecretValue,
        init::Initializer,
        inspect_envelope,
        key_provider::KeyProvider,
        open_envelope,
        profiles::ProfileOperations,
        testing::{MemoryKeyProvider, MemoryVaultStore, ReplacementFault},
    };

    const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;

    struct ObservedReader<'read> {
        read: &'read Cell<bool>,
    }

    impl Read for ObservedReader<'_> {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            self.read.set(true);
            Ok(0)
        }
    }

    fn initialized() -> (MemoryKeyProvider, MemoryVaultStore, ProfileName) {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        Initializer::new(&keys, &store)
            .initialize(INTERACTION)
            .unwrap();
        let profile = ProfileName::new("dev").unwrap();
        ProfileOperations::new(&keys, &store)
            .create(profile.clone(), INTERACTION)
            .unwrap();
        (keys, store, profile)
    }

    fn revision(keys: &MemoryKeyProvider, store: &MemoryVaultStore) -> u64 {
        let envelope = store.live().unwrap();
        let metadata = inspect_envelope(&envelope).unwrap();
        let key = keys.load(&metadata.key_id, INTERACTION).unwrap();
        open_envelope(&envelope, &key).unwrap().vault.revision()
    }

    fn snapshot_value(
        operations: &ProfileOperations<'_, MemoryKeyProvider, MemoryVaultStore>,
        profile: &ProfileName,
        name: &str,
    ) -> Vec<u8> {
        operations
            .snapshot(profile, INTERACTION)
            .unwrap()
            .variables()
            .iter()
            .find(|(candidate, _)| candidate.as_str() == name)
            .unwrap()
            .1
            .expose()
            .to_vec()
    }

    #[test]
    fn terminal_and_missing_profile_are_rejected_before_input_is_consumed() {
        let (keys, store, profile) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        let read = Cell::new(false);
        assert!(matches!(
            execute_import(
                &operations,
                &profile,
                ImportOptions {
                    dry_run: false,
                    replace_existing: false,
                },
                INTERACTION,
                true,
                ObservedReader { read: &read },
            ),
            Err(ImportCommandError::TerminalStdin)
        ));
        assert!(!read.get());

        let missing = ProfileName::new("missing").unwrap();
        assert!(matches!(
            execute_import(
                &operations,
                &missing,
                ImportOptions {
                    dry_run: false,
                    replace_existing: false,
                },
                INTERACTION,
                false,
                ObservedReader { read: &read },
            ),
            Err(ImportCommandError::Profile(ProfileOperationError::Domain(
                crate::DomainError::ProfileNotFound
            )))
        ));
        assert!(!read.get());
    }

    #[test]
    fn dry_run_reports_names_without_mutating_or_exposing_values() {
        let (keys, store, profile) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        operations
            .set(
                &profile,
                EnvironmentName::new("EXISTING").unwrap(),
                SecretValue::from_string("old-secret".into()).unwrap(),
                INTERACTION,
            )
            .unwrap();
        let before = store.live().unwrap();
        let ImportOutcome::DryRun { plan, .. } = execute_import(
            &operations,
            &profile,
            ImportOptions {
                dry_run: true,
                replace_existing: false,
            },
            INTERACTION,
            false,
            Cursor::new(b"EXISTING=CANARY-replacement\nNEW=CANARY-new\n"),
        )
        .unwrap() else {
            panic!("expected dry-run outcome")
        };
        assert_eq!(plan.created, [EnvironmentName::new("NEW").unwrap()]);
        assert_eq!(plan.collisions, [EnvironmentName::new("EXISTING").unwrap()]);
        assert_eq!(store.live().unwrap(), before);
        assert!(!format!("{plan:?}").contains("CANARY"));
    }

    #[test]
    fn a_new_collision_between_parse_and_commit_refuses_the_complete_import() {
        let (keys, store, profile) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        let before_parse = Cell::new(false);
        let result = execute_import_with_after_parse(
            &operations,
            &profile,
            ImportOptions {
                dry_run: false,
                replace_existing: false,
            },
            INTERACTION,
            false,
            Cursor::new(b"RACE=imported\nOTHER=value\n"),
            || {
                operations
                    .set(
                        &profile,
                        EnvironmentName::new("RACE").unwrap(),
                        SecretValue::from_string("concurrent".into()).unwrap(),
                        INTERACTION,
                    )
                    .unwrap();
                before_parse.set(true);
            },
        );
        assert!(before_parse.get());
        assert!(matches!(
            result,
            Err(ImportCommandError::Operation(
                ImportOperationError::Collisions(names)
            )) if names == [EnvironmentName::new("RACE").unwrap()]
        ));
        assert_eq!(
            operations.inspect(&profile, INTERACTION).unwrap().variables,
            [EnvironmentName::new("RACE").unwrap()]
        );
    }

    #[test]
    fn authorized_import_replaces_collisions_and_preserves_unmentioned_secrets_once() {
        let (keys, store, profile) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        for (name, value) in [("KEEP", "keep-secret"), ("CHANGE", "old-secret")] {
            operations
                .set(
                    &profile,
                    EnvironmentName::new(name).unwrap(),
                    SecretValue::from_string(value.into()).unwrap(),
                    INTERACTION,
                )
                .unwrap();
        }
        let revision_before = revision(&keys, &store);

        let ImportOutcome::Imported(receipt) = execute_import(
            &operations,
            &profile,
            ImportOptions {
                dry_run: false,
                replace_existing: true,
            },
            INTERACTION,
            false,
            Cursor::new(b"CHANGE=new-secret\nADDED=added-secret\n"),
        )
        .unwrap() else {
            panic!("expected imported outcome")
        };
        assert_eq!(
            receipt.plan.created,
            [EnvironmentName::new("ADDED").unwrap()]
        );
        assert_eq!(
            receipt.plan.collisions,
            [EnvironmentName::new("CHANGE").unwrap()]
        );
        assert_eq!(
            snapshot_value(&operations, &profile, "KEEP"),
            b"keep-secret"
        );
        assert_eq!(
            snapshot_value(&operations, &profile, "CHANGE"),
            b"new-secret"
        );
        assert_eq!(
            snapshot_value(&operations, &profile, "ADDED"),
            b"added-secret"
        );
        assert_eq!(revision(&keys, &store), revision_before + 1);
    }

    #[test]
    fn empty_input_is_a_noop_and_failed_commit_preserves_the_complete_old_envelope() {
        let (keys, store, profile) = initialized();
        let operations = ProfileOperations::new(&keys, &store);
        let before_empty = store.live().unwrap();
        assert!(matches!(
            execute_import(
                &operations,
                &profile,
                ImportOptions {
                    dry_run: false,
                    replace_existing: false,
                },
                INTERACTION,
                false,
                Cursor::new(b"# no variables\n"),
            )
            .unwrap(),
            ImportOutcome::NoVariables
        ));
        assert_eq!(store.live().unwrap(), before_empty);

        store.fail_next_replacement(ReplacementFault::NotCommitted);
        let before_failure = store.live().unwrap();
        let result = execute_import(
            &operations,
            &profile,
            ImportOptions {
                dry_run: false,
                replace_existing: false,
            },
            INTERACTION,
            false,
            Cursor::new(b"TOKEN=CANARY-must-not-commit\n"),
        );
        assert!(matches!(
            result,
            Err(ImportCommandError::Operation(
                ImportOperationError::Profile(ProfileOperationError::CommitNotCompleted)
            ))
        ));
        assert_eq!(store.live().unwrap(), before_failure);
        assert!(
            !store
                .live()
                .unwrap()
                .windows(b"CANARY".len())
                .any(|window| window == b"CANARY")
        );
    }
}
