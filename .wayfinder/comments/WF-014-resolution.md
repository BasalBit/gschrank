# Resolution: Decide the v1 executable name and command compatibility strategy

Resolved with Eraldo on 2026-08-07.

## Product and canonical executable

The product, Cargo package, and sole installed executable remain named
Gschrank and `gschrank`. V1 does not install a second executable, symlink, or
hard link under a short name. `gschrank` is the stable command for scripts,
automation, CI, installation, troubleshooting, and shells without Gschrank
integration.

The short `gs` spelling is rejected because it is Ghostscript's established
Unix executable. The two-character `gc` spelling is also rejected because it
is already a common Zsh alias and resolved to `git commit --verbose` in the
target user's current shell through the Oh My Zsh Git plugin. Other explored
three-letter spellings had existing shell-tool or CLI uses. The accepted
interactive shortcut is `gsch`: it is mnemonic, was free in the target
environment, and had no major executable or exact Homebrew package collision
at decision time. Local collision detection remains mandatory because no
short name can be globally reserved.

Background references:

- [Ghostscript invocation](https://ghostscript.readthedocs.io/en/latest/Use.html)
- [Oh My Zsh Git aliases](https://github.com/ohmyzsh/ohmyzsh/blob/master/plugins/git/README.md#aliases)

## One executable and two managed Zsh functions

In a configured Zsh shell, the managed integration exposes both `gsch` and
`gschrank` as public functions backed by one private dispatcher. They accept
the exact same command grammar, preserve the same arguments, output, and exit
status, and share one completion definition.

The dispatcher intercepts `load`, `reload`, `unload`, and every other operation
that must mutate the current parent shell. Ordinary commands delegate directly
to the canonical executable using a shell mechanism that bypasses the public
functions and aliases, avoiding recursion. Therefore both spellings behave
identically in an integrated interactive shell, while only `gschrank` is
promised outside it.

`gsch` is a shell convenience, not a machine-facing compatibility surface.
Scripts, shebangs, subprocesses, documentation intended for copying into
automation, and future unsupported-shell fallbacks use `gschrank`.

## Configuration and conflict behavior

`gschrank config` proposes enabling the `gsch` shortcut by default. Shortcut
enablement is an explicit non-secret preference and may be changed later
without touching the vault, profiles, values, current startup profile, or
canonical integration.

Before installing or enabling the shortcut, the Zsh editor checks the relevant
command namespaces for an existing alias, function, builtin, reserved word,
hashed command, or executable named `gsch`. A matching current Gschrank-managed
function is recognized as owned state for idempotent reconfiguration. Any
unrelated occupant is a conflict: Gschrank never removes, renames, shadows, or
overwrites it. Interactive configuration explains the safe conflict and may
continue by installing only the canonical `gschrank` function.

The canonical `gschrank` function is likewise installed only after the editor
has established that any pre-existing shell definition is either absent or
the recognized Gschrank-managed definition. The canonical executable itself
must resolve to the expected Gschrank binary and successfully satisfy the
versioned wrapper handshake before generated shell source is evaluated.

## Startup, upgrades, and late conflicts

The managed `.zshrc` block dynamically requests the current versioned wrapper
from `gschrank`, so a compatible binary upgrade refreshes the dispatcher, both
public functions, and their completion without rewriting the block. Upgrades
preserve the user's shortcut-enabled preference and never silently add,
remove, or rename a shortcut.

Each shell startup rechecks whether `gsch` is safe to define. If a newly
installed tool or later configuration now owns the name, Gschrank does not
shadow it: startup omits only the `gsch` function, emits a concise non-secret
warning, and continues canonical Gschrank initialization and configured
profile activation through `gschrank`. `doctor` reports the shortcut's enabled,
available, conflicting, shadowed, or disabled state using safe ownership
metadata and remediation guidance.

The existing shell-source transaction and no-leak rules apply equally to both
public functions. Shortcut failure cannot cause partial shell mutation,
plaintext output, or relaxed startup cleanup behavior.

## Documentation and help

Quickstarts and interactive examples lead with `gsch` after showing that it is
the optional managed shortcut for `gschrank`. The command reference remains one
grammar rather than duplicating alias-specific commands. Automation,
installation, recovery, and troubleshooting examples use `gschrank`.

`gschrank --help` may consistently display the canonical spelling even when
invoked through `gsch --help`; v1 does not add an invoked-as protocol merely to
rewrite usage text. Shell completion is registered for both functions when the
shortcut is active and only for `gschrank` when it is not.

## Removal boundaries

Disabling the shortcut removes the managed `gsch` function and its completion
from future shells and, when performed through the wrapper, the invoking shell.
It leaves the `gschrank` function, startup activation, current managed profile,
encrypted vault, and Keychain key unchanged.

Removing all shell integration deletes the managed `.zshrc` block, both public
functions, the private dispatcher, and their completions, and unloads the
invoking shell under the already accepted contract. It leaves the executable,
vault, and Keychain key in place. Package-manager removal of the executable and
destructive vault purge remain separate operations. Gschrank never removes an
unrelated command that occupies `gsch`.

The public operation is `gschrank shell uninstall`. It is idempotent and does
not require destructive confirmation. Direct executable invocation removes
persistent integration and gives current-shell guidance; invocation through the
managed wrapper unloads managed values and removes owned functions and
completions only after persistent removal succeeds.

## Stable namespace

The shortcut changes no persistent or machine-facing identifier. These retain
the full Gschrank namespace:

- the Cargo package and `gschrank` executable;
- macOS application-support and configuration paths;
- Keychain service `com.basalbit.gschrank.vault-key`;
- managed `.zshrc` markers and private shell-protocol identifiers;
- the `GSCHRANK_*` environment metadata namespace;
- package, documentation, and future platform-service identifiers; and
- vault, payload, key, and recovery formats.

A future Bash adapter may offer the same optional `gsch` policy with its own
command-namespace and startup checks. Adding Bash support neither changes the
canonical executable nor turns the shortcut into a cross-shell binary
guarantee.
