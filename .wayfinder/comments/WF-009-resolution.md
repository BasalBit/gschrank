# Resolution: Decide the portability seams for Bash and Linux

Resolved with Eraldo on 2026-08-06.

## Architecture rule

V1 uses one Rust codebase and one CLI binary with a portable policy core and a
small number of compile-time adapters. It does not build a runtime plugin
system, a universal platform abstraction, or speculative implementations for
unsupported environments.

A seam exists only where behavior is already known to vary or where a local
test adapter is necessary: secure key storage, transactional vault storage,
platform path discovery, shell source generation, and shell configuration
editing. Platform conditionals and target-specific dependencies remain inside
concrete adapters and the composition root. Domain and wire-format modules
contain no `cfg(target_os)` branches.

MacOS/Zsh are the only production adapters shipped and supported in v1.
Linux/Bash support follows by adding adapters at these seams and passing their
conformance suites, not by changing the core, vault format, or public command
model.

## Portable policy core

The portable core owns all behavioral policy:

- profile, environment-name, value, and resource-limit validation;
- profile creation, mutation, rename, deletion, snapshot, and replacement
  semantics;
- vault revisions, encryption-envelope use, and lifecycle transitions;
- initialization, backup, restore, reset, rebuild, recovery, and purge policy;
- whether an explicit failure preserves a shell or automatic startup clears
  inherited managed state; and
- portable typed outcomes and errors.

It accepts dependencies rather than constructing them and returns structured
results rather than performing terminal or shell side effects. A shell
operation yields a validated shell transition containing old managed names,
an optional new active profile, new name/value bindings, operation context,
and failure policy. The core never returns Zsh/Bash source, edits startup
files, chooses native paths, opens secure storage, prompts users, or formats
diagnostics.

Adapters supply mechanisms only. They cannot decide that a missing key permits
initialization, that failed startup should retain credentials, or that an
unsafe file should be repaired. This keeps lifecycle and profile policy local
to one deep module.

## KeyProvider seam

The portable synchronous `KeyProvider` interface has exactly three operations:

```text
load(key_id, interaction_policy) -> zeroizing 32-byte key
store_new(key_id, zeroizing 32-byte key, interaction_policy)
delete(key_id, interaction_policy)
```

`key_id` is the existing 128-bit portable identifier. Each adapter owns its
native namespace and attributes. `store_new` is create-only. There is no
update, upsert, get-or-create, fallback selection, broad search, or enumeration
operation. Every call explicitly receives `AllowPrompt` or `FailFast`.

Every adapter returns the previously selected semantic errors: `NotFound`,
`AlreadyExists`, `UserCancelled`, `AuthenticationFailed`,
`InteractionRequired`, `PermissionDenied`, `Unavailable`,
`InvalidKeyMaterial`, or `BackendFailure`. Safe native codes may be retained as
causes but never drive core policy.

`MacOsKeychainProvider` implements the v1 production interface. A future Linux
adapter may synchronously bridge to Secret Service/D-Bus internally. Linux
must never fall back automatically to a plaintext master-key file. Missing,
locked, headless, or unavailable secure storage returns the portable failure,
leaves ciphertext untouched, and makes automatic startup fail closed. Any
future passphrase or hardware provider is explicitly configured and receives
its own lifecycle design; backend switching is never automatic.

Tests use an in-memory KeyProvider adapter through the same interface.

## VaultStore seam

The core sees a deep transaction-level `VaultStore` interface rather than
filesystem primitives:

```text
shared_read(callback)
exclusive_transaction(callback)
```

The store retains the stable sidecar lock for the callback's full lifetime,
including secure-key access, authentication, mutation, and commit. A shared
read exposes the current encrypted envelope. An exclusive transaction permits
the core to read current encrypted state, preserve an exact encrypted recovery
artifact, atomically commit a new envelope, and stage or remove a specifically
identified internal artifact. Envelope bytes are opaque to the store;
lifecycle meaning remains in the core.

The concrete local store hides validated directory-relative operations,
ownership and modes, regular-file/symlink checks, locking, temporary-file and
stale-file grammar, complete writes, synchronization, atomic replacement, and
commit-outcome classification. Its portable errors distinguish missing state,
unsafe path, permission failure, lock failure, unsupported storage, ordinary
I/O failure, and an indeterminate commit outcome.

One shared Unix `LocalVaultStore` owns locking, path checks, artifact handling,
and transaction ordering. It has a private high-level durability adapter:

```text
durably_replace(validated_directory, temporary_file, destination)
    -> committed | not_committed | outcome_indeterminate
```

The macOS adapter performs `F_FULLFSYNC` and same-directory rename. The Linux
adapter performs file `fsync`, rename, and directory `fsync`. The core never
orchestrates individual sync or rename calls. APFS remains the only v1 support
claim; future Linux releases name and test their supported local filesystems.
Network filesystems stay unsupported.

## PlatformPaths seam

`PlatformPaths` returns typed locations for the private data directory, live
vault and stable lock, reserved initialization/rebuild/purge staging,
recovery directory, and non-secret application configuration. The macOS
adapter uses the native per-user application-support location. Linux later uses
XDG data/config locations and documented fallbacks.

The core never reads `HOME`, XDG variables, or platform directories. Shell
startup paths are explicitly excluded from PlatformPaths because they depend
on shell semantics. V1 exposes no general environment-variable override for
the live vault directory; tests inject locations internally and user-directed
backup paths remain explicit CLI arguments.

## ShellTransition and ShellEmitter seams

The core returns a structured, shell-neutral `ShellTransition`. A
shell-specific `ShellEmitter` provides:

```text
emit_wrapper(protocol_version)
emit_apply(transition)
emit_cleanup(validated_names)
```

Secret-bearing output is held in a zeroizing buffer. Each emitter owns a closed
grammar, quoting, readonly/type preflight, trace suppression, command-source
shape, and hostile-value corpus. Zsh and Bash may share domain types and the
transition behavior contract, but they do not share templates or assume
identical syntax.

The machine protocol is explicitly versioned. Managed blocks and internal
emitter endpoints state the shell kind and protocol version. A wrapper captures
all stdout, checks producer success, and evaluates only complete successful
output. Secret-bearing endpoints refuse terminal stdout, and their stdout is
reserved for generated source. Unsupported shells and protocol mismatches fail
before emitting source.

Shell selection is explicit. V1 configuration supports and displays only
`zsh`. A later multi-shell configuration accepts `--shell zsh` or `--shell
bash`; `$SHELL` may suggest an interactive default but never selects an adapter
without confirmation.

## ShellConfigEditor seam

Shell startup editing is a separate deep module:

```text
inspect() -> integration state
install(non_secret_managed_block)
replace(non_secret_managed_block)
uninstall()
```

The matching emitter produces the non-secret block; the editor safely places
it. `ZshConfigEditor` owns `ZDOTDIR`, `.zshrc`, explicit overrides, marker and
function/alias conflict detection, symlinks, `.zwc` shadowing, first-change
backup, concurrent-change checks, synchronization, and atomic replacement.
A future Bash editor owns `.bashrc` and login-shell discovery/sourcing rules.

Results distinguish unchanged, installed, updated, removed, conflict,
shadowed startup file, unsafe path, concurrent modification, permission
failure, and I/O failure. The editor never opens the vault, loads a key,
decrypts values, or generates secret-bearing apply source.

## Cross-shell managed-state protocol

Zsh and Bash use the same exported names-only metadata:

```text
GSCHRANK_ENV_PROTOCOL=1
GSCHRANK_ACTIVE_PROFILE=<validated profile name>
GSCHRANK_MANAGED_KEYS=<colon-separated validated variable names>
```

Managed names are sorted. The environment-name grammar excludes `:`, making
the manifest unambiguous, and the reserved `GSCHRANK_` namespace prevents
profile collisions. A child Bash shell can therefore identify and replace a
snapshot inherited from Zsh, and vice versa. This protocol does not synchronize
independent running shells.

Every adapter revalidates the protocol before using it. Unknown versions or
malformed metadata never become unchecked shell source. Explicit operations
fail without mutation; automatic startup follows the separately defined
fail-closed cleanup and warning policy.

## Stable format and command contracts

The exact same vault envelope and payload are used on macOS and Linux and are
independent of Zsh or Bash. They contain no operating-system, shell, native
path, Keychain, or Secret Service identity. Each secure-store adapter maps the
same public key ID into its native namespace. Names, UTF-8 values, limits,
sorting, cipher suite, integer widths, byte order, and schema retain their
existing meanings.

Copying vault bytes between platforms requires no format migration, but the
copy remains unusable until its exact key is transferred through a separately
authorized future mechanism. Adding or changing an adapter never causes a
healthy vault to be reinterpreted or rewritten automatically.

Future Linux/Bash support keeps the exact v1 public command grammar and domain
semantics. `config --shell …` is the only normal shell-selection difference.
Adapters may change mechanisms and safe diagnostic detail, not the meaning of
profiles, startup, activation, backup, restore, reset, rebuild, recovery,
status, doctor, or purge. Shell mutation always requires the matching installed
wrapper.

## Error and test contracts

Every seam uses typed portable errors rather than strings or native codes.
VaultStore, ShellEmitter, and ShellConfigEditor return the semantic categories
defined above for their interfaces. The CLI exhaustively renders only portable
outcomes; core policy never parses `errno`, `OSStatus`, D-Bus names, or shell
stderr.

Conformance suites are shared at each real seam:

- core behavior runs with in-memory KeyProvider and VaultStore adapters;
- secure-store adapters test create-only insertion, exact load/delete,
  interaction policy, invalid key length, and error mapping;
- VaultStore adapters test locks, permissions, symlinks, concurrency, every
  crash boundary, and all commit outcomes;
- envelope/payload modules use common golden byte vectors on macOS and Linux;
- each shell emitter runs the hostile-value corpus in the real shell and
  compares bytes inherited by a child process rather than display text; and
- each shell editor runs fixture-based conflict, idempotence, symlink,
  concurrent-edit, startup-file, and uninstall cases.

Tests assert through module interfaces. Private platform helpers are not
promoted into public seams merely for unit testing.

## Rust package and support matrix

V1 is one Cargo package. `src/lib.rs` contains portable modules, interfaces,
and adapters; `src/main.rs` is a thin composition root for CLI parsing,
prompting, adapter selection, outcome rendering, and exit status. Interfaces
remain `pub(crate)` unless a real external-library use appears. V1 makes no
Rust library compatibility promise and does not split prematurely into a
workspace of shallow crates.

Rust 1.89 is the initial MSRV, recorded in Cargo metadata and enforced in CI.
Target-specific dependencies prevent Apple libraries from compiling on Linux.
V1 ships/supports macOS/Zsh, while CI also compiles the complete CLI and runs
portable domain, codec, crypto, lifecycle, parsing, golden-vector, and
in-memory-adapter tests on Linux. A Linux composition root may return an
explicit unsupported-platform result until real adapters exist. No partial
Secret Service or Bash adapter is presented as supported. Linux/Bash support is
claimed only after its adapters pass the shared conformance suites.
