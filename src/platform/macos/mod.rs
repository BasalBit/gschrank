#![deny(unsafe_code)]

mod keychain;
mod paths;
mod store;

#[allow(unsafe_code)]
mod system;

#[allow(unsafe_code)]
mod terminal;

pub(crate) use keychain::MacOsKeychainProvider;
pub(crate) use paths::{MacOsPathError, MacOsPaths};
pub(crate) use store::LocalVaultStore;
pub(crate) use terminal::{HiddenInputError, read_hidden_stdin};
