# Gschrank

Gschrank is a Rust CLI for keeping named environment profiles in an encrypted
vault and loading them safely into a shell. macOS and Zsh are the first
supported platform and shell; the portable core is designed for a later Linux
and Bash adapter.

The project is currently under implementation. The portable core implements
the validated profile model, deterministic vault payload codec, and the
authenticated XChaCha20-Poly1305 envelope. On macOS, `gschrank init` now creates
an empty encrypted vault through atomic APFS persistence and stores its random
master key in the login Keychain. Authenticated `profile create`, `rename`,
`delete`, `list`, and names-only `inspect` operations atomically rewrite that
vault. `set` accepts a value only through a no-echo terminal prompt or explicit
non-terminal `--stdin`; `remove` deletes a named value, and neither command
prints secret data. `gschrank startup set <profile>` now safely installs or
updates one versioned `.zshrc` block, while `gschrank startup off` keeps shell
integration installed but clears inherited managed values in future shells.
The editor refuses symlinks, malformed markers, conflicting shell names,
concurrent changes, and compiled `.zshrc.zwc` shadowing; it preserves file mode,
keeps a first-change backup, and replaces through a synced same-directory file.
The versioned Zsh wrapper and private apply protocol support transactional
profile replacement, reload, and unload with inherited names-only metadata.
`gschrank shell uninstall` removes only managed persistent and current-shell
integration while retaining encrypted state, Keychain items, and backups.
Profile rename follows the configured startup reference, and deletion refuses
the startup profile until another profile is selected or automatic loading is
turned off.

The canonical executable is `gschrank`. Configured interactive Zsh shells also
expose the optional conflict-checked `gsch` function when that name is free.

## Development

The minimum supported Rust version is 1.89.

```console
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```
