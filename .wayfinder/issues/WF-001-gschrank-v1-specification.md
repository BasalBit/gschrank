---
id: WF-001
title: Find the way to an implementation-ready Gschrank v1 specification
label: wayfinder:map
status: closed
assignee: eraldo
parent:
blocked_by: []
resolution: ../comments/WF-001-resolution.md
---

## Destination

An implementation-ready product and technical specification for a Rust-based
Gschrank v1 on macOS and Zsh: encrypted named environment profiles, automatic
startup activation, safe profile replacement, and no routine plaintext output.

## Notes

- Domain: local secrets storage, Unix process environments, Zsh integration,
  macOS Keychain, and a portable Rust core.
- This is a planning map. It resolves decisions needed before implementation;
  it does not implement the CLI.
- Use primary-source security research, the `research`, `prototype`, and
  `grilling` skills where their ticket types require them. The Wayfinder skill's
  referenced `domain-modeling` skill is not installed, so model-domain work
  directly in the relevant grilling session.
- The v1 threat model prevents accidental disclosure through dotfiles,
  repositories, logs, command arguments, and routine agent file inspection. It
  does not defend against a compromised user account or a process inspecting
  already-decrypted child environments.
- v1 targets macOS and Zsh. Its key-provider, vault, and shell boundaries must
  admit Linux and Bash soon afterward without changing the profile model or
  vault format.
- A random master key lives in macOS Keychain; only authenticated encrypted
  data lives in Gschrank files.
- Profiles are named. One profile is active per shell. Switching profiles
  removes variables managed by the previous profile and leaves unrelated shell
  variables untouched.
- Setup edits `.zshrc` idempotently, asks which profile to activate, and loads
  it on every Zsh startup. Users can explicitly activate a different profile.
- Secret values enter through a hidden prompt or deliberate stdin, never a
  command argument. v1 has no command that prints decrypted values.
- v1 is local and single-user.

## Decisions so far

- [Research the macOS Keychain key-provider contract](WF-002-research-macos-keychain.md) — The practical CLI path is a create-only generic-password key in the user's login Keychain behind a semantic provider boundary.
- [Research the encrypted vault security envelope](WF-003-research-encrypted-vault.md) — Authenticated versioned encryption plus locked, synchronized atomic replacement can protect the local vault, with rollback and live-memory limits documented.
- [Research safe Zsh environment mutation and startup semantics](WF-004-research-zsh-environment.md) — A Zsh function must capture validated machine output before evaluation and track inherited variables through names-only metadata.
- [Decide the profile and active-shell domain model](WF-005-decide-profile-model.md) — Profiles are self-contained transactional snapshots with strict names, deterministic ownership-by-name replacement, and zero-or-one active profile per shell.
- [Decide the macOS Keychain backend and startup interaction policy](WF-011-decide-keychain-policy.md) — V1 uses a restricted login-Keychain item through a create-only native adapter, with explicit prompt policy and fail-closed automatic startup.
- [Prototype the Zsh setup and profile-activation contract](WF-007-prototype-zsh-integration.md) — A dynamic, idempotently managed Zsh wrapper provides transactional explicit operations, fail-closed startup, upgrade-safe initialization, and non-destructive uninstall behavior.
- [Decide the v1 vault envelope, payload, and persistence contract](WF-012-decide-vault-contract.md) — A single bounded XChaCha20-Poly1305 vault uses strict versioned binary formats, serialized atomic replacement, defensive permissions, and explicit security limits.
- [Decide vault initialization, lifecycle, and recovery behavior](WF-006-decide-vault-lifecycle.md) — Explicit crash-recoverable initialization, frozen failure states, encrypted backup and recovery bundles, recoverable reset/rebuild, and staged purge govern the full v1 vault lifecycle.
- [Prototype the v1 CLI and onboarding journey](WF-008-prototype-cli-onboarding.md) — A guided `config` flow and compact names-only command surface cover setup, profile editing, shell activation, diagnostics, and explicit recovery without value arguments or plaintext output.
- [Decide the portability seams for Bash and Linux](WF-009-decide-portability-seams.md) — A policy-rich portable core uses narrow secure-store, transactional-vault, platform-path, shell-emitter, and shell-editor interfaces with conformance-tested adapters and one stable format.
- [Decide the no-leak security and acceptance contract](WF-010-decide-security-contract.md) — V1 fixes explicit secret channels, forbidden observations, redaction and failure invariants, dependency controls, precise limitations, and a release-blocking canary/fault-injection suite.
- [Decide whether and how v1 imports existing environment files](WF-013-decide-env-import.md) — V1 provides a strict stdin-only, names-only-previewed, additive and transactional dotenv migration with explicit collision replacement and no plaintext-output or source-deletion path.
- [Decide the v1 executable name and command compatibility strategy](WF-014-decide-executable-name.md) — `gschrank` remains the sole canonical executable and stable namespace, while configured shells may safely expose the optional conflict-checked `gsch` shortcut through the same transactional wrapper.

## Not yet specified

- None currently.

## Out of scope

- Cloud synchronization and team secret sharing.
- Directory-based automatic profile switching.
- Defending secrets after they have been deliberately loaded into a process
  environment.
- Plaintext `show` or `get` commands.
- In-place master-key rotation and automatic old-key retirement; v1 uses a
  fresh-vault rebuild that retains the previous recovery pair.
- Raw master-key export and passphrase-encrypted portable recovery archives;
  v1 backups remain bound to their exact Keychain item.
- The post-v1 proxy execution mode (`gschrank run --profile … -- command`) and
  its authorization, process-replacement, signal, and environment-minimization
  behavior.
- Concrete Bash and Linux adapters and their support claims; v1 fixes and
  tests their seams but implements only macOS/Zsh production adapters.
- Packaging and distribution beyond the v1 installation contract.
