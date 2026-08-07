# Gschrank

Gschrank is a Rust CLI for keeping named environment profiles in an encrypted
vault and loading them safely into a shell. macOS and Zsh are the first
supported platform and shell; the portable core is designed for a later Linux
and Bash adapter.

The project is currently under implementation. The first milestone implements
the validated profile model, deterministic vault payload codec, and the
authenticated XChaCha20-Poly1305 envelope. Keychain persistence, local atomic
storage, and shell integration are the next milestone, so this build does not
yet store or load real credentials.

The canonical executable is `gschrank`. Configured interactive Zsh shells will
also be able to expose the optional `gsch` function once shell integration is
implemented.

## Development

The minimum supported Rust version is 1.89.

```console
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```
