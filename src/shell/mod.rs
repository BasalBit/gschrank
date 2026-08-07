#![forbid(unsafe_code)]

mod zsh;

use std::{error::Error, fmt};

use zeroize::Zeroizing;

use crate::{EnvironmentName, shell_transition::ShellTransition};

pub(crate) use zsh::{
    ZSH_MANAGED_BLOCK_END, ZSH_MANAGED_BLOCK_START, ZSH_SHORTCUT_METADATA, ZSH_STARTUP_METADATA,
    ZshEmitter, ZshManagedBlock,
};

/// Shell-specific source generation over validated shell-neutral inputs.
pub(crate) trait ShellEmitter {
    fn emit_wrapper(&self, shortcut: bool) -> String;

    fn emit_apply(
        &self,
        transition: &ShellTransition,
    ) -> Result<Zeroizing<Vec<u8>>, ShellEmitError>;

    fn emit_cleanup(&self, names: &[EnvironmentName])
    -> Result<Zeroizing<Vec<u8>>, ShellEmitError>;
}

/// A value-free shell-source generation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShellEmitError {
    SourceTooLarge,
}

impl fmt::Display for ShellEmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the shell transition is too large to encode safely")
    }
}

impl Error for ShellEmitError {}
