# Resolution: Research the macOS Keychain key-provider contract

Resolved on 2026-08-05 by `research-agent-keychain`.

The practical backend for an ordinary first-release Rust CLI is a generic
password item in the user's file-based login Keychain. Provisioning must use
create-only semantics so an existing master key can never be overwritten, and
the core must distinguish not-found, cancellation, authentication failure,
interaction-required, permission, unavailable, and invalid-key states. A
semantic `KeyProvider` boundary keeps Apple status codes and Linux Secret
Service details outside the vault core.

The research identifies file-Keychain longevity, binary trust across upgrades,
startup interaction policy, the final stable item identity, and Rust wrapper
selection as decisions still required before implementation.

Research asset:
[macOS Keychain key-provider research](/private/tmp/gschrank-research-keychain/docs/research/macos-keychain-key-provider.md)
on branch `research/macos-keychain-key-provider`, commit `0c79955`.

