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
    }
}
