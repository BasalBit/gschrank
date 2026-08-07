#![forbid(unsafe_code)]

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use super::system;

/// Native macOS locations used by Gschrank.
pub(crate) struct MacOsPaths {
    data_directory: PathBuf,
}

impl MacOsPaths {
    pub(crate) fn discover() -> Result<Self, MacOsPathError> {
        let home = system::home_directory().map_err(|_| MacOsPathError::HomeUnavailable)?;
        if !home.is_absolute() {
            return Err(MacOsPathError::UnsafeHome);
        }
        Ok(Self::from_home(&home))
    }

    fn from_home(home: &Path) -> Self {
        Self {
            data_directory: home
                .join("Library")
                .join("Application Support")
                .join("gschrank"),
        }
    }

    pub(crate) fn data_directory(&self) -> &std::path::Path {
        &self.data_directory
    }

    #[allow(dead_code)]
    pub(crate) fn live_vault(&self) -> PathBuf {
        self.data_directory.join("vault")
    }

    #[allow(dead_code)]
    pub(crate) fn stable_lock(&self) -> PathBuf {
        self.data_directory.join("vault.lock")
    }

    #[allow(dead_code)]
    pub(crate) fn initialization_candidate(&self) -> PathBuf {
        self.data_directory.join("vault.init.pending")
    }

    #[allow(dead_code)]
    pub(crate) fn rebuild_candidate(&self) -> PathBuf {
        self.data_directory.join("vault.rebuild.pending")
    }

    #[allow(dead_code)]
    pub(crate) fn recovery_directory(&self) -> PathBuf {
        self.data_directory.join("recovery")
    }

    #[allow(dead_code)]
    pub(crate) fn purge_staging_directory(&self) -> PathBuf {
        self.data_directory.join("purge.pending")
    }

    #[allow(dead_code)]
    pub(crate) fn configuration_file(&self) -> PathBuf {
        self.data_directory.join("config")
    }

    #[cfg(test)]
    pub(crate) fn at_data_directory(data_directory: PathBuf) -> Self {
        Self { data_directory }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacOsPathError {
    HomeUnavailable,
    UnsafeHome,
}

impl fmt::Display for MacOsPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HomeUnavailable => "the macOS home directory is unavailable",
            Self::UnsafeHome => "the macOS home directory is unsafe",
        })
    }
}

impl Error for MacOsPathError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_data_under_native_application_support() {
        let paths = MacOsPaths::from_home(Path::new("/Users/tester"));
        assert_eq!(
            paths.data_directory(),
            std::path::Path::new("/Users/tester/Library/Application Support/gschrank")
        );
        assert_eq!(paths.live_vault(), paths.data_directory().join("vault"));
        assert_eq!(
            paths.stable_lock(),
            paths.data_directory().join("vault.lock")
        );
        assert_eq!(
            paths.initialization_candidate(),
            paths.data_directory().join("vault.init.pending")
        );
        assert_eq!(
            paths.rebuild_candidate(),
            paths.data_directory().join("vault.rebuild.pending")
        );
        assert_eq!(
            paths.recovery_directory(),
            paths.data_directory().join("recovery")
        );
        assert_eq!(
            paths.purge_staging_directory(),
            paths.data_directory().join("purge.pending")
        );
        assert_eq!(
            paths.configuration_file(),
            paths.data_directory().join("config")
        );
    }
}
