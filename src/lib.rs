#![deny(unsafe_code)]

//! Portable security core for Gschrank.
//!
//! The crate deliberately keeps platform mechanisms out of the domain, codec,
//! and authenticated-envelope modules. macOS Keychain, local persistence, and
//! shell adapters will compose these modules without changing their formats or
//! policy.

mod cli;
mod codec;
mod config_command;
mod domain;
mod dotenv;
mod envelope;
mod import_command;
mod init;
mod key_provider;
mod profiles;
mod secret_input;
mod set_command;
mod shell;
mod shell_config;
mod shell_transition;
mod vault_store;

#[cfg(target_os = "macos")]
mod platform;

#[cfg(test)]
mod testing;

pub use cli::run_cli;
pub use codec::PayloadError;
pub use domain::{DomainError, EnvironmentName, Mutation, ProfileName, SecretValue, Vault};
pub use envelope::{
    EnvelopeError, EnvelopeMetadata, KeyId, MasterKey, OpenedVault, VaultId, inspect_envelope,
    open_envelope, seal_vault,
};

/// Maximum size of a complete encrypted vault envelope.
pub const MAX_ENVELOPE_SIZE: usize = 16 * 1024 * 1024;
/// Maximum number of profiles in one vault.
pub const MAX_PROFILES: usize = 256;
/// Maximum byte length of one profile name.
pub const MAX_PROFILE_NAME_BYTES: usize = 64;
/// Maximum number of variables in one profile.
pub const MAX_VARIABLES_PER_PROFILE: usize = 1_024;
/// Maximum byte length of one environment-variable name.
pub const MAX_VARIABLE_NAME_BYTES: usize = 255;
/// Maximum byte length of one value.
pub const MAX_VALUE_BYTES: usize = 256 * 1024;
/// Maximum combined bytes of variable names and values in one profile.
pub const MAX_PROFILE_BYTES: usize = 512 * 1024;
