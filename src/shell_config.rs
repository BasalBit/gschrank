#![forbid(unsafe_code)]

use crate::ProfileName;

/// Non-secret preferences represented by one managed shell-startup block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StartupConfiguration {
    profile: Option<ProfileName>,
    shortcut: bool,
}

impl StartupConfiguration {
    pub(crate) const fn new(profile: Option<ProfileName>, shortcut: bool) -> Self {
        Self { profile, shortcut }
    }

    pub(crate) const fn profile(&self) -> Option<&ProfileName> {
        self.profile.as_ref()
    }

    pub(crate) const fn shortcut(&self) -> bool {
        self.shortcut
    }

    pub(crate) fn with_profile(&self, profile: Option<ProfileName>) -> Self {
        Self::new(profile, self.shortcut)
    }

    pub(crate) fn without_shortcut(&self) -> Self {
        Self::new(self.profile.clone(), false)
    }
}

/// Safe state discovered from a shell startup file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ShellIntegrationState {
    Absent,
    Installed(StartupConfiguration),
}

impl ShellIntegrationState {
    pub(crate) fn configuration(&self) -> Option<&StartupConfiguration> {
        match self {
            Self::Absent => None,
            Self::Installed(configuration) => Some(configuration),
        }
    }
}

/// Observable outcome of placing a complete managed block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShellConfigEdit {
    Installed,
    Updated,
    Unchanged,
}
