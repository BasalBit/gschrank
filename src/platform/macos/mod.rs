#![deny(unsafe_code)]

mod backup;
mod keychain;
mod paths;
mod preferences;
mod restore_source;
mod store;
mod zsh_config;

#[allow(unsafe_code)]
mod system;

#[allow(unsafe_code)]
mod terminal;

pub(crate) use backup::EncryptedBackupWriter;
pub(crate) use keychain::MacOsKeychainProvider;
pub(crate) use paths::{MacOsPathError, MacOsPaths};
pub(crate) use preferences::{PreferenceError, ShellPreferenceStore, ShellPreferences};
pub(crate) use restore_source::EncryptedRestoreSource;
pub(crate) use store::LocalVaultStore;
pub(crate) use system::suppress_core_dumps;
pub(crate) use terminal::{HiddenInputError, read_hidden_stdin};
pub(crate) use zsh_config::{ShortcutDiagnostic, ZshConfigEditor, ZshConfigError, ZshDiagnostic};
