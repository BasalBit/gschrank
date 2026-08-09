# Gschrank

Gschrank stores named environment profiles in an authenticated encrypted vault
and loads them transactionally into Zsh. Secret values are accepted only by a
no-echo terminal prompt or deliberate non-terminal standard input. Public
output is safe-metadata-only and never directly reveals values or value
lengths.

Gschrank v1 supports macOS with Zsh. Linux builds exercise the portable core,
but Linux persistence and Bash integration are not supported yet.

## Install

Building requires Rust 1.89 or newer and the macOS command-line developer
tools.

```sh
git clone https://github.com/BasalBit/gschrank.git
cd gschrank
cargo install --locked --path .
```

The sole installed executable is `gschrank`. Guided configuration can install
an optional `gsch` Zsh function for interactive use; scripts and automation
should always use `gschrank`.

## Quick Start

Run the guided setup, then start a new Zsh process so its managed `.zshrc`
block can initialize the current shell:

```sh
gschrank config
exec zsh
```

The wizard creates or validates the vault, configures a profile, reads each
value without terminal echo, and optionally selects that profile for new
shells. If the optional shortcut was enabled, interactive commands can use
`gsch`:

```sh
gsch profile list
gsch profile inspect work
gsch load work
gsch reload
gsch unload
```

`load`, `reload`, and `unload` must run through the installed Zsh function
because an executable cannot mutate its parent shell. A failed explicit switch
leaves the current shell unchanged. Startup failure clears names identified by
valid inherited Gschrank metadata, prints a value-free warning, and still opens
Zsh. Cleanup is only best effort if that metadata was malformed or tampered
with.

## Secret Input

Interactive input is the default:

```sh
gschrank set work API_TOKEN
```

For deliberate noninteractive use, `--stdin` reads every byte through EOF and
rejects terminal input:

```sh
secret-producing-command | gschrank set work API_TOKEN --stdin
```

For `set --stdin`, Gschrank does not trim whitespace or trailing newlines and
empty input is a valid empty value. `import dotenv` is a separate deliberate
non-terminal stdin channel that parses its strict data-only dotenv syntax. Do
not place values in arguments, command substitutions, environment variables,
URLs, or project files. There is no plaintext `show`, `get`, `export`, JSON, or
debug mode.

## Commands

Use `gschrank --help` for the exact grammar. The public command groups are:

| Command | Purpose |
| --- | --- |
| `config [--rc-file <absolute-path>]` | Guided vault, profile, value, and Zsh setup |
| `init` | Create an empty vault or authenticate the existing vault |
| `profile create\|rename\|delete\|list\|inspect` | Manage profiles and names |
| `set`, `remove` | Change profile variables without printing values |
| `import dotenv` | Import a strict dotenv document from stdin |
| `startup set`, `startup off` | Configure activation for future Zsh processes |
| `load`, `reload`, `unload` | Transactionally change the current integrated shell |
| `status`, `doctor` | Show names-only state or value-free diagnostics |
| `backup`, `restore` | Copy or restore a Keychain-bound encrypted envelope |
| `rebuild`, `reset` | Create a fresh keyed vault with recovery preservation |
| `recovery list\|restore\|purge` | Manage durable internal recovery bundles |
| `shell uninstall` | Remove managed Zsh integration but retain vault data |
| `purge` | Remove managed local state and authenticated Keychain keys |

Restore over live state, rebuild, reset, recovery purge, and full purge use
typed interactive confirmation where required by their lifecycle. They have no
v1 force flag. Ordinary profile deletion, variable removal, and shell
uninstallation do not use typed confirmation.

Public success output uses stdout; warnings and errors use stderr. Stable v1
exit statuses are:

| Status | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Other runtime failure |
| `2` | Invalid command or arguments |
| `10` | Not initialized |
| `11` | Keychain access or interaction failure |
| `12` | Vault authentication, format, or key-material failure |
| `13` | Unsafe filesystem or shell-configuration state |
| `14` | Conflict, cancellation, or refused destructive operation |
| `15` | Commit outcome indeterminate |
| `130` | Interrupted by the user |

## Backup And Recovery

Backups contain authenticated ciphertext only and are created at an explicit
absolute path without overwriting an existing file. They do not contain the
master key:

```sh
gschrank backup /absolute/path/vault.backup
gschrank restore /absolute/path/vault.backup
```

A backup is usable only while its exact key remains in the macOS Keychain.
`restore`, `reset`, and `rebuild` preserve displaced encrypted state as an
internal recovery bundle. Inspect recovery metadata with:

```sh
gschrank recovery list
gschrank doctor
```

Recovery bundles do not expire and are deleted only by an explicit recovery
purge or full purge. Full purge does not delete user-directed backup files and
does not claim secure erasure. If the corresponding Keychain key is deleted or
permanently lost, all ciphertext encrypted with it is unrecoverable.

## Storage And Shell Files

Gschrank keeps private state under
`~/Library/Application Support/gschrank`. The directory is mode `0700`; vault,
lock, staging, and recovery files are current-user-owned mode `0600` regular
files. V1 durability guarantees apply only to local APFS.

Vault existence, timestamps, and unpadded ciphertext size are observable. The
size reflects aggregate encoded content and can reveal value-size information,
especially for a vault with one value. Gschrank does not claim size-hiding
encryption.

Setup owns one visibly marked, non-secret block in the configured startup file,
defaulting to `${ZDOTDIR:-$HOME}/.zshrc`, and keeps a first-change backup beside
it. It refuses symlinks, malformed or duplicate markers, command-name
conflicts, concurrent changes, and compiled `.zshrc.zwc` shadowing rather than
guessing.

See [SECURITY.md](SECURITY.md) for the threat model, security assumptions,
limitations, and private vulnerability-reporting process.

## Development

The committed lockfile is part of the reviewed release input.

```sh
cargo +1.89.0 test --locked
cargo +1.89.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.89.0 fmt --all -- --check
```

CI also checks RustSec advisories, dependency licenses and sources, duplicate
versions, the complete Linux target, and portable Linux tests.
