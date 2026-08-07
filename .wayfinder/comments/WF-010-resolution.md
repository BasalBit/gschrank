# Resolution: Decide the no-leak security and acceptance contract

Resolved with Eraldo on 2026-08-07.

## Security objective and classification

V1 prevents accidental disclosure through dotfiles, project files, command
arguments, ordinary output, diagnostics, history, Gschrank-owned persistence,
backups, and routine agent filesystem inspection. It does not prevent an
authorized same-user process from deliberately invoking Gschrank, reading an
already-loaded environment, or inspecting live memory.

The following are secret-bearing:

- the master key;
- every environment-variable value, including observable empty/nonempty state;
- decrypted payload bytes and parsed secret values;
- hidden-prompt and stdin buffers;
- generated shell apply source because it encodes values;
- any derived buffer, error, panic context, trace field, serialization, hash,
  fingerprint, comparison output, or diagnostic containing those bytes; and
- per-value lengths.

The following are intentional safe metadata and may appear in names-only
output:

- profile names and variable names;
- active/startup profile and the managed-name manifest;
- opaque vault and key IDs;
- envelope, payload, and shell-protocol versions;
- lifecycle state, authentication success/failure, permission state, and safe
  native error codes;
- aggregate profile/variable counts and logical revision after successful
  authentication; and
- encrypted envelope bytes and ordinary filesystem metadata, although no
  routine command dumps raw envelopes.

Authentication failure never reveals whether its cause was a wrong key,
corruption, tampering, or an authenticated-header mismatch. Value lengths,
fingerprints, and equality are never promoted to safe metadata.

## Secret input

V1 permits exactly two secret-input channels:

1. interactive input from a real terminal with echo disabled; and
2. explicit `--stdin`, which reads the complete non-terminal byte stream
   through EOF.

Secret values are forbidden in positional arguments, `--value` options,
`NAME=value` command syntax, environment variables used to configure
Gschrank, URLs, configuration files, or Gschrank-created temporary input files.
The CLI never asks a user to paste a secret into a shell command line.

Before requesting or consuming a value, Gschrank authenticates and completely
validates the vault, destination profile, and variable name. Interactive input
uses a no-echo reader outside shell line-editing/history frameworks. A scoped
terminal-state guard restores echo on success, error, cancellation, panic
unwinding, and handled signals. Gschrank never pre-fills, redisplays, confirms
by printing, summarizes, or copies the value to the clipboard.

`--stdin` rejects terminal stdin; callers must use deliberate pipe or
redirection input. Input is read into bounded zeroizing memory, preserved
exactly, and then checked against the agreed UTF-8, NUL, per-value, and
per-profile limits. Gschrank never trims spaces or trailing newlines. Empty
input is the valid empty value.

## Secret output

Every public command keeps stdout and stderr safe-metadata-only regardless of
whether either stream points to a terminal, pipe, or regular file. Redirection
does not unlock more revealing behavior. V1 has no plaintext `show`, `get`,
`export`, JSON, debug, reveal, or value-confirmation mode.

The sole secret-bearing output channel is the private versioned shell-emitter
endpoint used by the installed wrapper. It:

- is absent from ordinary help;
- requires the exact shell kind and protocol version;
- refuses terminal stdout;
- authenticates and validates the complete vault, shell metadata, transition,
  and generated source before writing any byte;
- reserves stdout exclusively for generated source; and
- sends only non-secret diagnostics to stderr.

The wrapper captures the complete output, checks successful exit, and evaluates
nothing after a producer, encoding, pipe-write, or protocol failure. Public
names-only commands also buffer their results until the operation succeeds
rather than printing partial lists.

## Process, shell, and terminal surfaces

Gschrank-created argument vectors and process titles contain only commands,
profile/variable names, user paths, opaque IDs, and flags. They never contain
values or master-key bytes. Gschrank never places an input value or master key
in an environment variable.

Native Keychain and cryptographic libraries are called in-process. Gschrank
does not invoke `security`, `openssl`, another shell, or any external tool to
handle secret data. Secret-bearing apply source travels only through an
anonymous pipe into a non-exported wrapper-local scalar. The wrapper locally
disables Zsh `XTRACE` and `VERBOSE` before capture, restores the caller's option
state afterward, and unsets the payload scalar immediately after evaluation.

Secrets never appear in filenames, process titles, lock names, backup names,
recovery names, temporary names, completion scripts, command examples, or
documentation. Public prompts and output keep terminal scrollback non-secret.
Pseudo-terminal behavior must prove value bytes do not enter terminal output or
shell history and that terminal echo is restored at every handled failure
point.

This contract does not claim to remove values already inherited by the
Gschrank process or deliberately installed into a shell or child environment.

## Filesystem, dotfiles, and backups

Gschrank never writes state relative to the current project directory and
never creates `.env`, plaintext cache, session, or secret-bearing dotfiles.

`.zshrc` and its first-change backup contain only the versioned managed block,
shell/protocol identifiers, startup profile name, and names-only metadata
logic. Gschrank configuration files contain only non-secret preferences and
paths. The private data directory is current-user-owned mode `0700`; vault,
lock, initialization, staging, recovery, and internal metadata files are
current-user-owned mode `0600` regular files under the already agreed symlink
and path checks.

Every vault, user backup, internal recovery bundle, initialization/rebuild
candidate, restore artifact, and purge artifact contains authenticated
ciphertext or non-secret metadata only. Master keys, plaintext payloads, values,
and generated shell source are never written to a filesystem path, including a
temporary path. User-directed backups use the same restrictive creation and
symlink rules. Persistence failure never falls back to a broader permission or
plaintext representation.

## Diagnostics, logging, and redaction

V1 has no telemetry, analytics, crash upload, or persistent application log.
Normal diagnostics go directly to stderr and contain only safe metadata.
Verbose output, enabled backtraces, developer builds, and test diagnostics do
not relax redaction.

Secret-bearing types do not implement or derive content-revealing `Debug`,
`Display`, ordinary serialization, equality diagnostics, or error conversion.
Errors are constructed from portable semantic categories and explicitly safe
fields, never by formatting a secret buffer or decrypted domain object. Native
Keychain/filesystem codes may be retained only after ensuring no secret input
was passed to the native diagnostic interface. Cryptographic failures remain
generic. Panic hooks print a generic failure and safe operation context only.

Test metrics may count operations and outcomes but never value lengths, hashes,
fingerprints, or content.

## Failure-mode requirements

Public failure returns nonzero and never emits secret-bearing stdout. Vault
mutation exposes the previous complete authenticated envelope or the new
complete authenticated envelope, never plaintext or a partial live file.

Explicit `load`, `reload`, and switch capture complete emitter output before
evaluation. Authentication, metadata, encoding, producer, or preflight failure
leaves the current shell unchanged. The shell adapter preflights every unset
and assignment before the first mutation and emits only fixed builtins with
mechanically valid source.

Automatic startup failure clears every valid name in inherited Gschrank
metadata, clears all Gschrank metadata, warns safely, and allows the shell to
open. If inherited metadata is malformed, cleanup is necessarily best effort
because omitted or corrupted names cannot be reconstructed safely. The warning
must say that the user should close the parent shell or manually unload.
Gschrank does not claim fail-closed cleanup against tampered metadata.

Unexpected interruption during shell evaluation, hostile traps, a modified
shell, or a hostile same-user process is outside the transaction guarantee.
Filesystem commit ambiguity is reported as indeterminate; retries reread
authoritative state and never assume that reported failure means no commit.

## Crash handling and memory limitations

Release builds retain unwinding so zeroizing containers drop where safe Rust
can unwind. The binary catches unexpected panics at the top-level command
boundary, uses a sanitized panic hook, drops owned secret state, and exits
nonzero. Panic messages, backtraces, and stderr never include decrypted objects
or values.

At startup Gschrank best-effort disables process core dumps through the native
platform mechanism. Failure does not block ordinary use; `doctor` reports a
safe warning. Gschrank creates and uploads no crash artifact. Tests inject
panics before and after decryption, shell generation, and persistence steps and
scan all owned files and diagnostic streams.

Forced aborts, OS crash reporters, memory snapshots, registers, allocator
remnants, swap, core capture that bypasses suppression, hostile memory
inspection, and secrets already in live environments remain outside the
guarantee. A crash during persistence still leaves only ciphertext artifacts
under the atomic-write contract.

## Routine agent inspection guarantee

An agent that reads the repository, current working directory, shell
configuration, Gschrank configuration, private vault directory, encrypted
backups, internal recovery artifacts, shell history, and normal public CLI
output must find no secret value or master-key material. Those surfaces contain
only source code, safe metadata, or authenticated ciphertext.

The guarantee does not apply to an agent that deliberately inspects an
already-loaded environment or process memory, or invokes the private
secret-bearing shell-emitter protocol through a pipe. These are authorized
same-user capabilities outside the v1 threat model and motivate the future
proxy-execution mode.

## Dependency and unsafe-code policy

`Cargo.lock` is committed and releases use its reviewed dependency graph. The
secret-path dependency set remains small and every direct dependency is
reviewed for maintenance, security history, features, default-feature
expansion, build scripts, and transitive dependencies. Unused default features
are disabled and v1 has no runtime network dependency.

RustSec advisory and dependency-policy checks run in CI. V1 does not release
with a known unmitigated vulnerability affecting secret handling.
Cryptography, randomness, zeroization, hidden-input, shell-emitter, Keychain,
and persistence dependency changes require security-focused review.

Portable domain, codec, cryptographic orchestration, lifecycle, and shell
generation modules use `#![forbid(unsafe_code)]`. Unsafe code is permitted only
inside narrowly scoped platform adapters when no reviewed safe wrapper supplies
the required operation. Every unsafe block documents its invariants and has
focused tests and review. A malicious dependency remains outside the threat
model; these controls reduce accidental supply-chain exposure rather than
claiming to eliminate it.

## Output and exit statuses

Public success output uses stdout; diagnostics and warnings use stderr. The
stable v1 exit statuses are:

```text
0    success
1    other runtime failure
2    invalid command or arguments
10   not initialized
11   secure-store access or interaction failure
12   vault authentication, format, or key-material failure
13   unsafe filesystem or shell-configuration state
14   conflict, cancellation, or refused destructive operation
15   commit outcome indeterminate
130  interrupted by the user
```

Authentication status `12` intentionally does not distinguish wrong key,
corruption, or tampering. Exit codes never encode secret presence, length,
content, equality, or change. Shell wrappers propagate emitter failure and
evaluate only status `0` output.

## Release-blocking acceptance suite

Every no-leak test uses unique canary values containing recognizable markers,
Unicode, quotes, control characters, whitespace, embedded/trailing newlines,
and shell metacharacters. The harness records and scans:

- process arguments and titles;
- public stdout and stderr;
- pseudo-terminal transcripts and shell history;
- Zsh trace and verbose output;
- every Gschrank-created or edited file;
- live vaults, ordinary temporaries, initialization/rebuild/restore/purge
  staging, backups, and recovery bundles;
- verbose diagnostics, error chains, panic output, and backtraces; and
- state after fault injection at every Keychain, random-generation, encrypt,
  decrypt, decode, encode, pipe, shell preflight/evaluation, write, sync,
  rename, reopen, and cleanup boundary.

A canary may appear only in the test's secret-input source, Gschrank's transient
secret memory, the private anonymous shell-source pipe, and the designated
target shell/child environment assertion. It must occur nowhere else.

The suite also verifies restrictive permissions, symlink refusal, echo-state
restoration, explicit-operation preservation, startup cleanup and malformed
metadata warnings, authentication failure, old-or-new persistence, and
indeterminate commit recovery. Property and fuzz tests cover the envelope
parser, payload decoder, managed-metadata parser, shell emitter, size limits,
and malformed/trailing input. Shell tests compare bytes in a child environment,
not a display representation.

The complete canary and macOS/Zsh integration matrix is a mandatory release
gate for v1.

## Published claims

V1 ships with `SECURITY.md` documenting the exact threat model, routine-agent
guarantee, visible metadata, secret channels, Keychain/encryption/filesystem/
shell assumptions, support matrix, recovery limits, permanent-key-loss
consequence, explicit exclusions, and a private vulnerability-reporting
process or contact.

Documentation describes observable tested guarantees. It does not claim that
secrets never touch memory, that leakage is impossible, or use vague language
such as “military-grade encryption.”
