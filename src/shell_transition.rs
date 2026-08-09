#![forbid(unsafe_code)]

use std::{error::Error, fmt};

use crate::{EnvironmentName, ProfileName, SecretValue, domain::ProfileSnapshot};

pub(crate) const ENV_PROTOCOL_NAME: &str = "GSCHRANK_ENV_PROTOCOL";
pub(crate) const ACTIVE_PROFILE_NAME: &str = "GSCHRANK_ACTIVE_PROFILE";
pub(crate) const MANAGED_KEYS_NAME: &str = "GSCHRANK_MANAGED_KEYS";
pub(crate) const ENV_PROTOCOL_VERSION: &str = "1";

/// Whether a shell transition was explicitly requested or runs at startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationContext {
    Explicit,
    AutomaticStartup,
}

/// Policy to apply when producing a transition fails before shell mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailurePolicy {
    PreserveCurrent,
    ClearInherited,
}

/// Validated names-only state inherited from the invoking shell.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ManagedState {
    active_profile: Option<ProfileName>,
    managed_names: Vec<EnvironmentName>,
}

impl ManagedState {
    pub(crate) const fn empty() -> Self {
        Self {
            active_profile: None,
            managed_names: Vec::new(),
        }
    }

    pub(crate) fn from_metadata(
        protocol: Option<&str>,
        active_profile: Option<&str>,
        managed_names: Option<&str>,
    ) -> Result<Self, ManagedStateError> {
        if protocol.is_none() && active_profile.is_none() && managed_names.is_none() {
            return Ok(Self::empty());
        }
        let protocol = protocol.ok_or(ManagedStateError::Incomplete)?;
        let active_profile = active_profile.ok_or(ManagedStateError::Incomplete)?;
        let managed_names = managed_names.ok_or(ManagedStateError::Incomplete)?;

        if protocol != ENV_PROTOCOL_VERSION {
            return Err(ManagedStateError::UnsupportedProtocol);
        }

        let active_profile = ProfileName::new(active_profile)
            .map_err(|_| ManagedStateError::InvalidActiveProfile)?;
        let managed_names = parse_managed_names(managed_names)?;
        Ok(Self {
            active_profile: Some(active_profile),
            managed_names,
        })
    }

    pub(crate) fn active_profile(&self) -> Option<&ProfileName> {
        self.active_profile.as_ref()
    }

    pub(crate) fn managed_names(&self) -> &[EnvironmentName] {
        &self.managed_names
    }
}

fn parse_managed_names(value: &str) -> Result<Vec<EnvironmentName>, ManagedStateError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for raw in value.split(':') {
        let name = EnvironmentName::new(raw).map_err(|_| ManagedStateError::InvalidManagedNames)?;
        if names
            .last()
            .is_some_and(|previous: &EnvironmentName| previous >= &name)
        {
            return Err(ManagedStateError::InvalidManagedNames);
        }
        names.push(name);
    }
    Ok(names)
}

/// A value-free validation error for inherited managed-state metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedStateError {
    Incomplete,
    UnsupportedProtocol,
    InvalidActiveProfile,
    InvalidManagedNames,
    MissingActiveProfile,
}

impl fmt::Display for ManagedStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Incomplete => "inherited Gschrank shell metadata is incomplete",
            Self::UnsupportedProtocol => {
                "inherited Gschrank shell metadata uses an unsupported protocol"
            }
            Self::InvalidActiveProfile => "inherited Gschrank active-profile metadata is invalid",
            Self::InvalidManagedNames => "inherited Gschrank managed-name metadata is invalid",
            Self::MissingActiveProfile => "no Gschrank profile is active in this shell",
        })
    }
}

impl Error for ManagedStateError {}

/// A shell-neutral, secret-owning transition ready for one shell adapter.
///
/// This type deliberately implements neither `Debug` nor `Clone`.
pub(crate) struct ShellTransition {
    previous_names: Vec<EnvironmentName>,
    next: Option<ProfileSnapshot>,
    context: OperationContext,
    failure_policy: FailurePolicy,
}

impl ShellTransition {
    pub(crate) fn load(
        current: ManagedState,
        next: ProfileSnapshot,
        context: OperationContext,
    ) -> Self {
        Self {
            previous_names: current.managed_names,
            next: Some(next),
            context,
            failure_policy: match context {
                OperationContext::Explicit => FailurePolicy::PreserveCurrent,
                OperationContext::AutomaticStartup => FailurePolicy::ClearInherited,
            },
        }
    }

    pub(crate) fn reload_profile(current: &ManagedState) -> Result<ProfileName, ManagedStateError> {
        current
            .active_profile()
            .cloned()
            .ok_or(ManagedStateError::MissingActiveProfile)
    }

    pub(crate) fn previous_names(&self) -> &[EnvironmentName] {
        &self.previous_names
    }

    pub(crate) fn active_profile(&self) -> Option<&ProfileName> {
        self.next.as_ref().map(ProfileSnapshot::name)
    }

    pub(crate) fn bindings(
        &self,
    ) -> impl ExactSizeIterator<Item = (&EnvironmentName, &SecretValue)> {
        let variables = self
            .next
            .as_ref()
            .map_or(&[][..], ProfileSnapshot::variables);
        variables.iter().map(|(name, value)| (name, value))
    }

    pub(crate) const fn context(&self) -> OperationContext {
        self.context
    }

    pub(crate) const fn failure_policy(&self) -> FailurePolicy {
        self.failure_policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecretValue, Vault};

    #[test]
    fn validates_only_complete_canonical_inherited_metadata() {
        assert_eq!(
            ManagedState::from_metadata(None, None, None).unwrap(),
            ManagedState::empty()
        );

        let state =
            ManagedState::from_metadata(Some("1"), Some("work"), Some("API_TOKEN:DATABASE_URL"))
                .unwrap();
        assert_eq!(
            state.active_profile(),
            Some(&ProfileName::new("work").unwrap())
        );
        assert_eq!(
            state.managed_names(),
            &[
                EnvironmentName::new("API_TOKEN").unwrap(),
                EnvironmentName::new("DATABASE_URL").unwrap(),
            ]
        );

        assert_eq!(
            ManagedState::from_metadata(Some("1"), None, Some("TOKEN")).unwrap_err(),
            ManagedStateError::Incomplete
        );
        assert_eq!(
            ManagedState::from_metadata(Some("2"), Some("work"), Some("TOKEN")).unwrap_err(),
            ManagedStateError::UnsupportedProtocol
        );
        assert_eq!(
            ManagedState::from_metadata(Some("1"), Some("work"), Some("B:A")).unwrap_err(),
            ManagedStateError::InvalidManagedNames
        );
        assert_eq!(
            ManagedState::from_metadata(Some("1"), Some("work"), Some("A:A")).unwrap_err(),
            ManagedStateError::InvalidManagedNames
        );
        assert_eq!(
            ManagedState::from_metadata(Some("1"), Some("work"), Some("GSCHRANK_BAD")).unwrap_err(),
            ManagedStateError::InvalidManagedNames
        );
    }

    #[test]
    fn generated_metadata_combinations_are_revalidated_without_panicking() {
        let protocols = [None, Some(""), Some("1"), Some("2"), Some("🗝")];
        let profiles = [None, Some("work"), Some("bad name"), Some("GSCHRANK_BAD")];
        let manifests = [
            None,
            Some(""),
            Some("A"),
            Some("A:B"),
            Some("B:A"),
            Some("A:A"),
            Some("GSCHRANK_BAD"),
            Some("A::B"),
        ];
        for protocol in protocols {
            for profile in profiles {
                for manifest in manifests {
                    let result = ManagedState::from_metadata(protocol, profile, manifest);
                    let expected_valid = matches!(
                        (protocol, profile, manifest),
                        (None, None, None) | (Some("1"), Some("work"), Some("" | "A" | "A:B"))
                    );
                    assert_eq!(
                        result.is_ok(),
                        expected_valid,
                        "unexpected metadata result for {protocol:?}, {profile:?}, {manifest:?}"
                    );
                    if let Ok(state) = result {
                        assert!(
                            state
                                .managed_names()
                                .windows(2)
                                .all(|pair| pair[0] < pair[1])
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn transition_owns_one_snapshot_and_fixed_failure_policy() {
        let mut vault = Vault::empty();
        let work = ProfileName::new("work").unwrap();
        vault.create_profile(work.clone()).unwrap();
        vault
            .set(
                &work,
                EnvironmentName::new("TOKEN").unwrap(),
                SecretValue::from_string("canary-secret".to_owned()).unwrap(),
            )
            .unwrap();
        let snapshot = vault.into_profile_snapshot(&work).unwrap();
        let current =
            ManagedState::from_metadata(Some("1"), Some("old"), Some("OLD_TOKEN")).unwrap();

        let transition =
            ShellTransition::load(current, snapshot, OperationContext::AutomaticStartup);
        assert_eq!(transition.active_profile(), Some(&work));
        assert_eq!(transition.previous_names().len(), 1);
        assert_eq!(transition.bindings().len(), 1);
        assert_eq!(transition.context(), OperationContext::AutomaticStartup);
        assert_eq!(transition.failure_policy(), FailurePolicy::ClearInherited);
    }

    #[test]
    fn reload_requires_an_active_profile() {
        assert_eq!(
            ShellTransition::reload_profile(&ManagedState::empty()).unwrap_err(),
            ManagedStateError::MissingActiveProfile
        );
    }
}
