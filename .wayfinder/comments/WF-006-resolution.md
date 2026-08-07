# Resolution: Decide vault initialization, lifecycle, and recovery behavior

Resolved with Eraldo on 2026-08-06.

## Lifecycle states and invariants

The vault lifecycle has these externally meaningful states:

- **Uninitialized:** no live vault exists and there is no recoverable pending
  initialization.
- **Initialization pending:** a reserved encrypted initial envelope exists while
  its Keychain/file transaction is incomplete.
- **Ready:** the live vault, referenced Keychain item, authentication, payload,
  paths, ownership, and permissions all validate.
- **Temporarily inaccessible:** the vault exists but Keychain interaction was
  cancelled, denied, unavailable, or disallowed by the current interaction
  policy.
- **Frozen unreadable:** key material is missing or invalid, authentication
  fails, the format is malformed or unsupported, or persistent state is
  ambiguous.
- **Purge pending:** explicitly selected internal artifacts have been staged
  for destructive key and ciphertext removal, but that sequence has not
  completed.

Only explicit lifecycle operations transition persistent state. Ordinary
profile commands and shell startup never initialize, replace, repair, reset,
or promote vault data. No operation emits shell mutations or acts on domain
data until the relevant envelope has authenticated and its entire payload has
validated.

## Explicit first initialization

Only `gschrank init`, or a guided configuration flow that announces and invokes
the same operation, may create a vault. `load`, `set`, profile creation, and
shell startup return a non-secret `NotInitialized` result with guidance when
the vault is absent. Initialization creates an empty vault at logical revision
zero; profile creation and startup-profile selection are separate visible
onboarding steps.

Initialization holds the exclusive sidecar lock and uses a reserved encrypted
staging envelope such as `vault.init.pending`:

1. Validate the private directory and confirm that no live vault exists.
2. Generate independent vault and key IDs plus a 32-byte master key.
3. Encode the empty payload, encrypt it, and durably write the complete
   envelope to the mode-`0600` pending file.
4. Store the key under its exact ID using create-only Keychain semantics.
5. Atomically rename the pending envelope to the live vault and perform every
   required persistence synchronization.
6. Reopen and authenticate the committed vault before reporting success.

A clean key-store failure before a Keychain item is created removes the
unusable pending envelope. After interruption, repeated initialization reads
the pending header and performs an exact key lookup. If that key exists and
authenticates the pending envelope, initialization completes the commit. If
the key is definitively absent, the pending ciphertext is unrecoverable and
may be discarded before a fresh initialization attempt. Transient or denied
Keychain access leaves it untouched. A present key that does not authenticate
the pending file freezes the state for explicit diagnosis; Gschrank neither
deletes nor replaces it.

Random key-ID collision reported as `AlreadyExists` never overwrites the
existing item. Before a key has been committed, initialization may discard its
new pending candidate and retry with newly generated identifiers and key
material.

## Repeated initialization

`gschrank init` is idempotent only for a healthy installation. It authenticates
and validates an existing live vault, reports that Gschrank is already
initialized, returns success, and performs no mutation. Any missing,
inaccessible, invalid, or non-authenticating key and any malformed or
unsupported live vault return the appropriate recovery error without creating
a replacement.

A live vault takes precedence over `vault.init.pending`. If the live vault is
healthy, a conflicting pending initialization is preserved for `doctor` or an
explicit repair operation rather than guessed away.

## Keychain and unreadable-vault failures

Every Keychain failure preserves persistent state. Interactive commands use
the previously decided prompt policy. Cancellation, authentication failure,
required-but-disallowed interaction, denied access, unavailability, and backend
failure remain distinct non-secret results. A missing exact item is
`VaultKeyMissing`; it never triggers key creation. Secret item data other than
exactly 32 bytes is `InvalidKeyMaterial`; Gschrank never repairs or overwrites
it.

Explicit profile operations preserve the current shell when key access fails.
Automatic shell startup retains its previously agreed fail-closed exception:
it clears inherited Gschrank-managed names and metadata, emits a non-secret
warning, and allows Zsh to open.

Corrupt, tampered, mismatched, structurally invalid, or unsupported vault data
puts the vault in a frozen state. Gschrank performs no profile read, mutation,
shell output, automatic fallback, key replacement, repair, or reset. The live
file remains byte-for-byte unchanged. Authentication failure is deliberately
generic because Gschrank cannot safely distinguish corruption, tampering, a
wrong key, or an authenticated-header mismatch.

`gschrank doctor` may report lifecycle stage, envelope compatibility, path and
permission status, whether the exact Keychain item exists, and other safe
metadata. It never reports decrypted profile names, variable names, or values.
Recovery requires an explicit restore, reset, recovery-bundle operation, or
purge.

## Interrupted writes and cleanup

When the live vault authenticates successfully, it is authoritative.
Gschrank may automatically remove an abandoned ordinary write temporary only
while holding the exclusive lock and only if all of these are true:

- its basename matches Gschrank's exact random temporary-file grammar;
- it is inside the validated private directory;
- it is a regular, current-user-owned, mode-`0600` file; and
- it is not a reserved initialization, recovery, rebuild, restore, or purge
  artifact.

An ordinary mutation temporary is never promoted to live state. Cleanup
failure warns without invalidating a healthy vault. When the live vault is
missing, unexpected temporaries remain untouched for `doctor`; only the
reserved initialization-pending protocol completes automatically. A pending
initialization found beside a live vault also remains untouched until explicit
repair.

## Encrypted backups

V1 backups contain only the encrypted vault envelope. They never contain or
export a raw master key and are useful only while their exact Keychain item
exists. They protect against accidental vault deletion, corruption, and
unwanted logical changes, but do not protect against Keychain-key loss or
provide portable machine recovery.

Backup creation is explicit and user-directed; v1 keeps no automatic rolling
history. It holds a shared lock, authenticates and completely validates the
live vault, then copies the exact envelope without changing its identity,
nonce, payload, or revision. The destination is created as a current-user-owned
mode-`0600` regular file without following symlinks. Existing destinations are
not replaced without explicit request. Writes use a same-directory temporary,
synchronization, and atomic replacement where supported. V1 guarantees backup
durability only on local APFS, though users may copy the resulting ciphertext
elsewhere at their own durability risk.

## Restore

Restore holds the exclusive lock and authenticates and fully validates the
selected backup using its exact Keychain key. With an existing live vault, the
backup's vault ID must match and the user must explicitly confirm replacement.
Before replacement, Gschrank preserves the exact current live file—healthy or
unreadable—as a clearly named, mode-`0600` internal recovery artifact. Failure
to preserve it aborts restore.

Gschrank atomically installs the selected backup, performs required
synchronization, reopens it, and authenticates it before reporting success.
The source backup is unchanged. Its logical revision is preserved, making
restore an explicit, accepted rollback. When no live vault exists, any valid
backup whose exact Keychain key is available may be installed directly.

Restore does not silently change shell-startup configuration. If the selected
startup profile is absent from the restored vault, automatic activation fails
closed until the user chooses a valid profile.

## Recoverable reset

Reset means starting with a new empty vault while preserving an escape hatch.
It requires interactive typed confirmation and has no unattended force flag in
v1. Under the exclusive lock, Gschrank moves the live vault and conflicting
initialization state into a clearly identified internal recovery bundle in a
mode-`0700` directory. It retains every referenced old Keychain item.

Reset disables automatic startup-profile selection because the new empty vault
cannot satisfy it. When invoked through the Zsh wrapper, it transactionally
unloads the current shell. Direct CLI invocation explains that a child process
cannot modify its parent shell. Gschrank begins explicit initialization of a
new empty vault only after the recovery bundle is durably committed. If new
initialization fails, the recovery bundle remains and Gschrank stays
uninitialized. External user-created backups are never modified.

## Fresh-vault rebuild

V1 provides a fresh-vault rebuild operation as a safer alternative to in-place
master-key rotation. Rebuild requires a healthy authenticated live vault and
holds the exclusive lock throughout its commit protocol:

1. Decrypt and fully validate the complete logical vault.
2. Durably preserve an exact encrypted copy of the old vault as an internal
   recovery bundle.
3. Generate new vault and key IDs plus a new 32-byte master key.
4. Encode the same profiles and values in a new logical vault starting at
   revision zero, and durably write a reserved encrypted rebuild candidate.
5. Store the new key under its exact ID with create-only Keychain semantics.
6. Authenticate the candidate, atomically replace the live vault, synchronize,
   reopen, and authenticate the committed result.

Before replacement, interruption leaves the old live vault authoritative;
after replacement, the new vault is authoritative. Reserved rebuild state
allows an interrupted operation to be diagnosed or resumed without guessing.
The old recovery envelope and its old Keychain key are always retained until a
separate explicit recovery-bundle purge.

Because every profile is copied, startup-profile selection remains valid and
existing shells retain their already-loaded snapshots. Rebuild creates a new
logical vault identity; it is not an in-place key rotation and it does not
automatically retire the old key.

## Recovery bundles

Recovery bundles created by restore, reset, or rebuild never expire and are
never deleted automatically. V1 provides operations to list, validate,
restore, and explicitly purge one. Listing exposes only creation time, reason,
vault ID, key ID, and authentication status—not decrypted profile or variable
names.

Purging a bundle requires typed confirmation that external backups using its
key may become unreadable. Before deleting a Keychain item, Gschrank verifies
that neither the live vault nor another internal recovery bundle references
that ID. Bundle purge first stages the selected ciphertext, then deletes the
exact key and removes the staged artifact. Interruption remains recognizable
and resumable. A key ID that cannot be established safely from an authenticated
artifact is not guessed or deleted.

## Destructive full purge

Full purge is the only intentionally irreversible v1 lifecycle. It requires
interactive typed confirmation, has no unattended force flag, and clearly
warns that external backups will become unusable. It removes future shell
startup integration and, when invoked through the Zsh wrapper, unloads the
invoking shell. Other running shells and processes cannot be remotely cleared.

Under the exclusive lock, purge moves the live vault, reserved pending state,
and all internal recovery bundles into a private purge-staging area. It
authenticates artifacts where possible and collects only their exact referenced
Gschrank Keychain IDs. It deletes those Keychain items, then removes staged
ciphertext, configuration, and internal metadata. Cancellation or deletion
failure stops the process and retains recognizable purge-pending state so the
user can retry or recover what remains. User-directed backups outside the
private Gschrank directory are never discovered or deleted.

Purge does not claim secure erasure. Ciphertext may remain in APFS snapshots,
backups, or storage remnants. Once a referenced master key has been deleted,
every remaining copy encrypted by it is intentionally unrecoverable.

## Deferred rotation and irrecoverable loss

V1 has no in-place master-key rotation or automatic old-key retirement. The
wire envelope supports a later protocol, while fresh-vault rebuild provides a
safe v1 way to renew the active vault identity and master key without deleting
the previous recovery pair.

V1 also has no raw-key export or passphrase-encrypted portable recovery
archive. If a referenced Keychain item is permanently lost, its vault, internal
recovery artifacts, and external encrypted backups cannot be decrypted.
Gschrank preserves or explicitly purges those ciphertext artifacts; moving
forward requires an explicit reset to a new vault and re-entry of secrets.
