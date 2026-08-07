#![forbid(unsafe_code)]

use std::{
    error::Error,
    fmt,
    io::{IsTerminal, Read, Write},
};

use crate::{
    EnvironmentName, Mutation, ProfileName, SecretValue,
    init::{InitError, InitOutcome, Initializer},
    key_provider::{InteractionPolicy, KeyProvider},
    profiles::{ProfileOperationError, ProfileOperations},
    secret_input::{SecretInputError, SecretInputMode, read_secret},
    set_command::{SetCommandError, execute_set},
    vault_store::VaultStore,
};

const MAX_VISIBLE_INPUT_BYTES: usize = 4 * 1024;

/// The non-secret choices produced by the guided vault journey.
pub(crate) struct ConfigSelection {
    pub(crate) profile: ProfileName,
    pub(crate) startup: bool,
    pub(crate) shortcut: bool,
    pub(crate) created_vault: bool,
    pub(crate) variables_changed: usize,
}

pub(crate) enum ConfigJourneyOutcome {
    Cancelled,
    Selected(ConfigSelection),
}

/// Semantic prompts used by the guided journey.
///
/// This is intentionally narrower than terminal I/O: tests can script user
/// decisions without exposing secret bytes to arguments, logs, or output.
pub(crate) trait ConfigPrompter {
    fn announce(&mut self, message: &str) -> Result<(), ConfigPromptError>;
    fn confirm_initialization(&mut self) -> Result<bool, ConfigPromptError>;
    fn profile_name(&mut self, default: &str) -> Result<String, ConfigPromptError>;
    fn variable_name(&mut self) -> Result<Option<String>, ConfigPromptError>;
    fn secret(&mut self, variable: &EnvironmentName) -> Result<SecretValue, SecretInputError>;
    fn confirm_startup(&mut self, profile: &ProfileName) -> Result<bool, ConfigPromptError>;
    fn confirm_shortcut(&mut self, default: bool) -> Result<bool, ConfigPromptError>;
}

pub(crate) fn run_config_journey<K, S, P>(
    initializer: &Initializer<'_, K, S>,
    operations: &ProfileOperations<'_, K, S>,
    prompts: &mut P,
    interaction: InteractionPolicy,
    shortcut_default: bool,
) -> Result<ConfigJourneyOutcome, ConfigJourneyError>
where
    K: KeyProvider,
    S: VaultStore,
    P: ConfigPrompter,
{
    let (profiles, created_vault) = match operations.list(interaction) {
        Ok(profiles) => {
            prompts.announce("Existing encrypted vault found; it will not be recreated.")?;
            (profiles, false)
        }
        Err(ProfileOperationError::NotInitialized) => {
            prompts.announce(
                "No vault was found. Configuration can initialize an empty encrypted vault now.",
            )?;
            if !prompts.confirm_initialization()? {
                prompts
                    .announce("Configuration cancelled before initialization; nothing changed.")?;
                return Ok(ConfigJourneyOutcome::Cancelled);
            }
            prompts.announce("Initializing the encrypted vault and its macOS Keychain key...")?;
            let outcome = initializer.initialize(interaction)?;
            let created = matches!(outcome, InitOutcome::Created { .. });
            prompts.announce(match outcome {
                InitOutcome::Created { .. } => "Initialized an empty encrypted vault.",
                InitOutcome::AlreadyInitialized { .. } => {
                    "Another process initialized the vault; using that healthy vault."
                }
            })?;
            (operations.list(interaction)?, created)
        }
        Err(error) => return Err(error.into()),
    };

    let profile = loop {
        let entered = prompts.profile_name("dev")?;
        let entered = entered.trim();
        let candidate = if entered.is_empty() { "dev" } else { entered };
        match ProfileName::new(candidate) {
            Ok(profile) => break profile,
            Err(error) => prompts.announce(&format!(
                "Invalid profile name ({error}); use lowercase letters, digits, '.', '_' or '-'."
            ))?,
        }
    };

    if profiles.iter().any(|existing| existing == &profile) {
        prompts.announce(&format!(
            "Using existing profile '{}'; stored values were not displayed.",
            profile.as_str()
        ))?;
    } else {
        prompts.announce(&format!("Creating profile '{}'...", profile.as_str()))?;
        operations.create(profile.clone(), interaction)?;
        prompts.announce(&format!("Created profile '{}'.", profile.as_str()))?;
    }

    prompts.announce(
        "Add variable names one at a time. Leave the variable name blank when finished.",
    )?;
    let mut variables_changed = 0;
    while let Some(entered) = prompts.variable_name()? {
        let entered = entered.trim();
        if entered.is_empty() {
            break;
        }
        let variable = match EnvironmentName::new(entered) {
            Ok(variable) => variable,
            Err(error) => {
                prompts.announce(&format!(
                    "Invalid variable name ({error}); no secret value was requested."
                ))?;
                continue;
            }
        };
        let output_name = variable.clone();
        let receipt = execute_set(operations, &profile, variable, interaction, || {
            prompts.secret(&output_name)
        })?;
        variables_changed += 1;
        prompts.announce(&format!(
            "{} variable '{}' in profile '{}'; its value was not displayed.",
            match receipt.mutation {
                Mutation::Created => "Created",
                Mutation::Updated => "Updated",
            },
            output_name.as_str(),
            profile.as_str()
        ))?;
    }

    let startup = prompts.confirm_startup(&profile)?;
    let shortcut = prompts.confirm_shortcut(shortcut_default)?;
    Ok(ConfigJourneyOutcome::Selected(ConfigSelection {
        profile,
        startup,
        shortcut,
        created_vault,
        variables_changed,
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigPromptError {
    TerminalRequired,
    Cancelled,
    InvalidInput,
    IoFailure,
}

impl ConfigPromptError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::TerminalRequired | Self::InvalidInput => 2,
            Self::Cancelled => 130,
            Self::IoFailure => 1,
        }
    }
}

impl fmt::Display for ConfigPromptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TerminalRequired => "config requires terminal input and error output",
            Self::Cancelled => "configuration input was cancelled",
            Self::InvalidInput => "configuration input was invalid or too long",
            Self::IoFailure => "configuration input or output failed",
        })
    }
}

impl Error for ConfigPromptError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigJourneyError {
    Prompt(ConfigPromptError),
    Init(InitError),
    Profile(ProfileOperationError),
    Set(SetCommandError),
}

impl ConfigJourneyError {
    pub(crate) const fn exit_code(self) -> u8 {
        match self {
            Self::Prompt(error) => error.exit_code(),
            Self::Init(error) => error.exit_code(),
            Self::Profile(error) => error.exit_code(),
            Self::Set(error) => error.exit_code(),
        }
    }
}

impl fmt::Display for ConfigJourneyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prompt(error) => error.fmt(formatter),
            Self::Init(error) => error.fmt(formatter),
            Self::Profile(error) => error.fmt(formatter),
            Self::Set(error) => error.fmt(formatter),
        }
    }
}

impl Error for ConfigJourneyError {}

impl From<ConfigPromptError> for ConfigJourneyError {
    fn from(error: ConfigPromptError) -> Self {
        Self::Prompt(error)
    }
}

impl From<InitError> for ConfigJourneyError {
    fn from(error: InitError) -> Self {
        Self::Init(error)
    }
}

impl From<ProfileOperationError> for ConfigJourneyError {
    fn from(error: ProfileOperationError) -> Self {
        Self::Profile(error)
    }
}

impl From<SetCommandError> for ConfigJourneyError {
    fn from(error: SetCommandError) -> Self {
        Self::Set(error)
    }
}

pub(crate) struct TerminalConfigPrompter;

impl TerminalConfigPrompter {
    pub(crate) fn new() -> Result<Self, ConfigPromptError> {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(ConfigPromptError::TerminalRequired);
        }
        Ok(Self)
    }

    fn visible(prompt: &str) -> Result<String, ConfigPromptError> {
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        stderr
            .write_all(prompt.as_bytes())
            .and_then(|()| stderr.flush())
            .map_err(|_| ConfigPromptError::IoFailure)?;
        read_visible_line()
    }

    fn confirm(&mut self, prompt: &str, default: bool) -> Result<bool, ConfigPromptError> {
        loop {
            let suffix = if default { " [Y/n]: " } else { " [y/N]: " };
            let answer = Self::visible(&format!("{prompt}{suffix}"))?;
            match answer.trim().to_ascii_lowercase().as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => self.announce("Please answer 'yes' or 'no'.")?,
            }
        }
    }
}

impl ConfigPrompter for TerminalConfigPrompter {
    fn announce(&mut self, message: &str) -> Result<(), ConfigPromptError> {
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        writeln!(stderr, "{message}").map_err(|_| ConfigPromptError::IoFailure)
    }

    fn confirm_initialization(&mut self) -> Result<bool, ConfigPromptError> {
        self.confirm("Initialize Gschrank now?", true)
    }

    fn profile_name(&mut self, default: &str) -> Result<String, ConfigPromptError> {
        Self::visible(&format!("Profile to create or configure [{default}]: "))
    }

    fn variable_name(&mut self) -> Result<Option<String>, ConfigPromptError> {
        Self::visible("Variable name: ").map(Some)
    }

    fn secret(&mut self, variable: &EnvironmentName) -> Result<SecretValue, SecretInputError> {
        self.announce(&format!(
            "Enter the value for '{}'; terminal echo will be disabled.",
            variable.as_str()
        ))
        .map_err(|_| SecretInputError::IoFailure)?;
        read_secret(SecretInputMode::HiddenTerminal)
    }

    fn confirm_startup(&mut self, profile: &ProfileName) -> Result<bool, ConfigPromptError> {
        self.confirm(
            &format!("Load '{}' in every new Zsh shell?", profile.as_str()),
            true,
        )
    }

    fn confirm_shortcut(&mut self, default: bool) -> Result<bool, ConfigPromptError> {
        self.confirm("Enable the optional 'gsch' shell shortcut?", default)
    }
}

fn read_visible_line() -> Result<String, ConfigPromptError> {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut bytes = Vec::with_capacity(64);
    loop {
        let mut byte = [0_u8; 1];
        match stdin.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Err(ConfigPromptError::Cancelled),
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if bytes.len() == MAX_VISIBLE_INPUT_BYTES {
                    return Err(ConfigPromptError::InvalidInput);
                }
                bytes.push(byte[0]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                return Err(ConfigPromptError::Cancelled);
            }
            Err(_) => return Err(ConfigPromptError::IoFailure),
        }
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|_| ConfigPromptError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::{
        DomainError,
        init::Initializer,
        testing::{MemoryKeyProvider, MemoryVaultStore},
    };

    const INTERACTION: InteractionPolicy = InteractionPolicy::FailFast;

    struct ScriptedPrompter {
        initialize: bool,
        profiles: VecDeque<String>,
        variables: VecDeque<Option<String>>,
        secrets: VecDeque<String>,
        startup: bool,
        shortcut: bool,
        announcements: Vec<String>,
        secret_requests: Vec<String>,
    }

    impl ScriptedPrompter {
        fn new() -> Self {
            Self {
                initialize: true,
                profiles: VecDeque::from([String::new()]),
                variables: VecDeque::from([None]),
                secrets: VecDeque::new(),
                startup: true,
                shortcut: true,
                announcements: Vec::new(),
                secret_requests: Vec::new(),
            }
        }
    }

    impl ConfigPrompter for ScriptedPrompter {
        fn announce(&mut self, message: &str) -> Result<(), ConfigPromptError> {
            self.announcements.push(message.to_owned());
            Ok(())
        }

        fn confirm_initialization(&mut self) -> Result<bool, ConfigPromptError> {
            Ok(self.initialize)
        }

        fn profile_name(&mut self, _default: &str) -> Result<String, ConfigPromptError> {
            self.profiles
                .pop_front()
                .ok_or(ConfigPromptError::Cancelled)
        }

        fn variable_name(&mut self) -> Result<Option<String>, ConfigPromptError> {
            self.variables
                .pop_front()
                .ok_or(ConfigPromptError::Cancelled)
        }

        fn secret(&mut self, variable: &EnvironmentName) -> Result<SecretValue, SecretInputError> {
            self.secret_requests.push(variable.as_str().to_owned());
            let secret = self
                .secrets
                .pop_front()
                .ok_or(SecretInputError::Interrupted)?;
            SecretValue::from_string(secret).map_err(SecretInputError::InvalidValue)
        }

        fn confirm_startup(&mut self, _profile: &ProfileName) -> Result<bool, ConfigPromptError> {
            Ok(self.startup)
        }

        fn confirm_shortcut(&mut self, _default: bool) -> Result<bool, ConfigPromptError> {
            Ok(self.shortcut)
        }
    }

    #[test]
    fn cancellation_before_initialization_changes_nothing() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        let initializer = Initializer::new(&keys, &store);
        let operations = ProfileOperations::new(&keys, &store);
        let mut prompts = ScriptedPrompter::new();
        prompts.initialize = false;

        assert!(matches!(
            run_config_journey(&initializer, &operations, &mut prompts, INTERACTION, true,)
                .unwrap(),
            ConfigJourneyOutcome::Cancelled
        ));
        assert!(store.live().is_none());
        assert_eq!(keys.key_count(), 0);
    }

    #[test]
    fn initializes_configures_and_never_requests_invalid_variable_values() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        let initializer = Initializer::new(&keys, &store);
        let operations = ProfileOperations::new(&keys, &store);
        let mut prompts = ScriptedPrompter::new();
        prompts.profiles = VecDeque::from(["INVALID NAME".into(), "work".into()]);
        prompts.variables = VecDeque::from([
            Some("NOT-VALID".into()),
            Some("API_TOKEN".into()),
            Some(String::new()),
        ]);
        prompts.secrets = VecDeque::from(["CANARY-super-secret".into()]);

        let ConfigJourneyOutcome::Selected(selection) =
            run_config_journey(&initializer, &operations, &mut prompts, INTERACTION, true).unwrap()
        else {
            panic!("expected completed configuration")
        };
        assert_eq!(selection.profile, ProfileName::new("work").unwrap());
        assert!(selection.created_vault);
        assert_eq!(selection.variables_changed, 1);
        assert_eq!(prompts.secret_requests, ["API_TOKEN"]);
        assert_eq!(
            operations
                .inspect(&selection.profile, INTERACTION)
                .unwrap()
                .variables,
            [EnvironmentName::new("API_TOKEN").unwrap()]
        );
        assert!(
            prompts
                .announcements
                .iter()
                .all(|message| !message.contains("CANARY"))
        );
    }

    #[test]
    fn rerun_uses_an_existing_vault_and_profile_without_reinitializing() {
        let keys = MemoryKeyProvider::new();
        let store = MemoryVaultStore::new();
        let initializer = Initializer::new(&keys, &store);
        initializer.initialize(INTERACTION).unwrap();
        let operations = ProfileOperations::new(&keys, &store);
        operations
            .create(ProfileName::new("dev").unwrap(), INTERACTION)
            .unwrap();
        let initial_store_calls = keys.store_calls();
        let mut prompts = ScriptedPrompter::new();
        prompts.shortcut = false;

        let ConfigJourneyOutcome::Selected(selection) =
            run_config_journey(&initializer, &operations, &mut prompts, INTERACTION, false)
                .unwrap()
        else {
            panic!("expected completed configuration")
        };
        assert!(!selection.created_vault);
        assert_eq!(selection.profile, ProfileName::new("dev").unwrap());
        assert_eq!(keys.store_calls(), initial_store_calls);
        assert!(!selection.shortcut);
        assert!(
            prompts
                .announcements
                .iter()
                .any(|message| message.contains("Existing encrypted vault"))
        );
    }

    #[test]
    fn visible_line_reader_rules_are_bounded_and_value_free() {
        assert_eq!(MAX_VISIBLE_INPUT_BYTES, 4096);
        assert_eq!(
            ConfigPromptError::InvalidInput.to_string(),
            "configuration input was invalid or too long"
        );
        assert_eq!(
            ConfigJourneyError::Prompt(ConfigPromptError::Cancelled).exit_code(),
            130
        );
        assert!(matches!(
            EnvironmentName::new("GSCHRANK_PRIVATE"),
            Err(DomainError::ReservedEnvironmentName)
        ));
    }
}
