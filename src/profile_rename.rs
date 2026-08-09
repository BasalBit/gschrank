#![forbid(unsafe_code)]

use crate::{ProfileName, VaultId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProfileRenameIntent {
    pub(crate) vault_id: VaultId,
    pub(crate) old: ProfileName,
    pub(crate) new: ProfileName,
    pub(crate) rc_file: std::path::PathBuf,
    pub(crate) shortcut: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VaultRenameObservation {
    pub(crate) vault_id: VaultId,
    pub(crate) old_exists: bool,
    pub(crate) new_exists: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupRenameObservation {
    Old,
    New,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileRenameAction {
    UpdateStartup,
    RenameVault,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProfileRenameStateError {
    VaultChanged,
    AmbiguousProfiles,
}

pub(crate) fn next_action(
    intent: &ProfileRenameIntent,
    vault: VaultRenameObservation,
    startup: StartupRenameObservation,
) -> Result<ProfileRenameAction, ProfileRenameStateError> {
    if vault.vault_id != intent.vault_id {
        return Err(ProfileRenameStateError::VaultChanged);
    }
    match (vault.old_exists, vault.new_exists, startup) {
        (true, false, StartupRenameObservation::Old)
        | (false, true, StartupRenameObservation::Old) => Ok(ProfileRenameAction::UpdateStartup),
        (true, false, StartupRenameObservation::New | StartupRenameObservation::Other) => {
            Ok(ProfileRenameAction::RenameVault)
        }
        (false, true, StartupRenameObservation::New | StartupRenameObservation::Other) => {
            Ok(ProfileRenameAction::Complete)
        }
        (true, true, _) | (false, false, _) => Err(ProfileRenameStateError::AmbiguousProfiles),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> ProfileRenameIntent {
        ProfileRenameIntent {
            vault_id: VaultId::from_bytes([1; 16]),
            old: ProfileName::new("old").unwrap(),
            new: ProfileName::new("new").unwrap(),
            rc_file: "/tmp/.zshrc".into(),
            shortcut: true,
        }
    }

    fn vault(old_exists: bool, new_exists: bool) -> VaultRenameObservation {
        VaultRenameObservation {
            vault_id: VaultId::from_bytes([1; 16]),
            old_exists,
            new_exists,
        }
    }

    #[test]
    fn rolls_forward_each_recoverable_cross_resource_state() {
        let intent = intent();
        assert_eq!(
            next_action(&intent, vault(true, false), StartupRenameObservation::Old),
            Ok(ProfileRenameAction::UpdateStartup)
        );
        assert_eq!(
            next_action(&intent, vault(true, false), StartupRenameObservation::New),
            Ok(ProfileRenameAction::RenameVault)
        );
        assert_eq!(
            next_action(&intent, vault(false, true), StartupRenameObservation::Old),
            Ok(ProfileRenameAction::UpdateStartup)
        );
        assert_eq!(
            next_action(&intent, vault(false, true), StartupRenameObservation::New),
            Ok(ProfileRenameAction::Complete)
        );
        assert_eq!(
            next_action(&intent, vault(false, true), StartupRenameObservation::Other),
            Ok(ProfileRenameAction::Complete)
        );
    }

    #[test]
    fn rejects_stale_or_ambiguous_vault_state() {
        let intent = intent();
        assert_eq!(
            next_action(
                &intent,
                VaultRenameObservation {
                    vault_id: VaultId::from_bytes([2; 16]),
                    old_exists: true,
                    new_exists: false,
                },
                StartupRenameObservation::Old,
            ),
            Err(ProfileRenameStateError::VaultChanged)
        );
        for state in [vault(true, true), vault(false, false)] {
            assert_eq!(
                next_action(&intent, state, StartupRenameObservation::New),
                Err(ProfileRenameStateError::AmbiguousProfiles)
            );
        }
    }
}
