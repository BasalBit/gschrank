# Security Policy

## Supported Versions

Security fixes are provided for the latest v1 release line.

| Version | Supported |
| --- | --- |
| Latest `0.1.x` | Yes |
| Older versions | No |

V1 supports macOS, Zsh, and local APFS persistence. Linux compilation and
portable-core tests do not constitute Linux or Bash product support. Network
filesystems are unsupported.

## Reporting A Vulnerability

Do not open a public issue for a suspected vulnerability or include real
secrets in a report. Email the maintainer privately at
<eraldo_hasanaj@hotmail.com>.

Include the affected version, macOS and Zsh versions, reproduction steps,
impact, and only synthetic test data. You should receive an acknowledgement
within seven days. Disclosure timing will be coordinated after validation and
a remediation plan.

## Security Objective

Gschrank v1 is designed to prevent accidental disclosure through project and
shell files, command arguments, ordinary stdout and stderr, diagnostics, shell
history, Gschrank-owned persistence, encrypted backups, and routine filesystem
inspection by coding agents.

An agent that reads the repository, current working directory, Gschrank-managed
shell configuration, Gschrank configuration and storage, encrypted backups,
recovery artifacts, shell history, and normal public CLI output should find no
Gschrank-managed secret value or master-key material introduced there by
Gschrank. Those managed surfaces contain source code, safe metadata, or
authenticated ciphertext. Gschrank preserves unrelated pre-existing shell-file
content and does not claim to remove secrets another tool or user stored there.

This is not a claim that secrets never enter memory or that leakage is
impossible.

## Secret And Visible Data

Secret data includes master keys, environment-variable values, decrypted
payloads, terminal/stdin buffers, and generated shell apply source. Per-value
lengths are treated as sensitive and are not directly reported by public CLI
output. The encrypted envelope is not padded, however, so its observable size
reflects aggregate encoded content and may reveal value-size information,
especially when only one value exists.

The following metadata is intentionally visible:

- Profile names and variable names.
- Active and startup profile names and the managed-name manifest.
- Opaque vault and key IDs and protocol versions.
- Lifecycle, authentication, permission, and safe native error status.
- Aggregate counts and logical revision after successful authentication.
- Authenticated ciphertext and ordinary filesystem metadata.

Authentication failure deliberately does not distinguish a wrong key,
corruption, tampering, or an authenticated-header mismatch.

## Secret Channels

The public input channels for values are a real terminal with echo disabled,
`set --stdin` from a non-terminal stream, and the stdin-only `import dotenv`
command. Input is bounded and held in zeroizing containers where practical.
`set --stdin` preserves its value exactly; dotenv import parses its strict
data-only syntax without expansion. Gschrank does not accept values in
arguments, `NAME=value` command syntax, configuration environment variables,
URLs, or files it creates.

All public stdout and stderr are safe-metadata-only. The sole secret-bearing
output is a private, versioned shell-emitter protocol used by the installed Zsh
wrapper. It refuses terminal output, emits only after complete authentication
and validation, travels through an anonymous pipe, and is evaluated only after
a successful complete capture. The wrapper locally disables Zsh `XTRACE` and
`VERBOSE` and promptly unsets its payload scalar.

## Security Assumptions

### Keychain

Each vault has an independent random 32-byte master key stored as opaque data
in the current user's default file-based macOS Keychain, normally the login
Keychain. Items use create-only insertion and exact lookup under service
`com.basalbit.gschrank.vault-key`; ordinary operations never overwrite a key.
macOS may prompt when authorization is required. Security depends on the
Keychain, account, and executable access controls remaining trustworthy.

### Encryption

Vault payloads use a versioned XChaCha20-Poly1305 authenticated envelope with a
fresh random nonce. Encryption protects values at rest and detects modification
before payload use. It does not protect values after they are deliberately
loaded into an environment or against a process that can access the key or live
memory.

### Filesystem

The private data directory and files are restricted to the current user.
Gschrank refuses unsafe links and ambiguous paths, writes ciphertext through
same-directory staged replacement, synchronizes commits, and authenticates
committed state before reporting success. The v1 durability claim applies to
local APFS only. Purge is logical key and file deletion, not secure erasure;
copies may remain in snapshots, backups, or storage remnants.

### Shell

The shell transaction assumes the installed managed Zsh wrapper and an
unmodified, non-hostile shell during evaluation. Explicit transition failure
leaves the current shell unchanged. Startup failure clears names identified by
valid inherited Gschrank metadata and allows Zsh to open. Cleanup is only best
effort when inherited metadata has been tampered with because omitted names
cannot be reconstructed safely.

## Recovery Limits

Backups and internal recovery bundles contain encrypted envelopes but no raw
key. They are machine-bound to the exact Keychain item. Gschrank v1 has no key
export, passphrase recovery archive, portable machine recovery, in-place key
rotation, automatic recovery expiry, or automatic old-key retirement.

`rebuild` creates a new vault identity and key while retaining the prior
encrypted vault and key as recovery state. `reset` preserves old state before
creating an independently keyed empty vault. `restore` preserves displaced live
state. Recovery bundles persist until explicitly purged.

Permanent loss or deletion of a referenced Keychain key makes every associated
vault, recovery bundle, and external backup undecryptable. Moving forward
requires an explicit reset and re-entry of values. Full purge warns about this
consequence, does not discover or delete external backups, and cannot clear
values already loaded in other processes.

## Explicit Exclusions

The v1 guarantee does not cover:

- A same-user process deliberately reading an already-loaded environment,
  invoking the private emitter through a pipe, or inspecting process memory.
- Compromised administrator/root access, a compromised OS, Keychain, Gschrank
  binary, compiler, or malicious dependency.
- Hostile shell hooks, traps, plugins, debugger attachment, or interruption
  during shell evaluation.
- Forced aborts, OS crash reporters, memory snapshots, registers, allocator
  remnants, swap, or core capture that bypasses best-effort suppression.
- Values inherited before Gschrank starts or copied elsewhere after loading.
- Secure deletion from APFS snapshots, external backups, or physical media.

Gschrank has no telemetry, analytics, crash upload, or persistent application
log. Release builds unwind panics, install a value-free panic diagnostic, and
best-effort disable core dumps, but these measures do not extend the threat
model to hostile live-memory inspection.

## Dependency Policy

Releases use the committed `Cargo.lock`. CI checks RustSec advisories, licenses,
registry and Git sources, duplicate versions, the Rust 1.89 MSRV, and the macOS
and portable Linux test matrices. Cryptography, randomness, zeroization,
terminal, shell, Keychain, and persistence dependency changes require
security-focused review. A malicious dependency remains outside the threat
model.
