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
vault. Secret-value entry and shell integration are not implemented yet, so the
current CLI cannot store or load environment values.

The canonical executable is `gschrank`. Configured interactive Zsh shells will
also be able to expose the optional `gsch` function once shell integration is
implemented.

## Development

The minimum supported Rust version is 1.89.

```console
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```
