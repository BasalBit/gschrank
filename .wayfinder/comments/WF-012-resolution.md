# Resolution: Decide the v1 vault envelope, payload, and persistence contract

Resolved with Eraldo on 2026-08-05.

## Cryptographic envelope

V1 implements exactly one cipher suite: suite `0x0001`,
XChaCha20-Poly1305 with a 32-byte key, 24-byte nonce, and 16-byte postfix
authentication tag. Every encryption attempt obtains a fresh random nonce from
the operating system. Randomness failure aborts the write; nonces are never
derived, counted, persisted separately, or reused for retries. Unknown suites
are non-destructive read errors, with no fallback. The implementation enables
the cipher library's key-zeroization feature.

The file begins with this fixed 80-byte public header. Unsigned integers are
big-endian:

| Offset | Length | Field | V1 requirement |
| ---: | ---: | --- | --- |
| 0 | 8 | Magic | ASCII `GSCHRANK` |
| 8 | 2 | Envelope version | `0x0001` |
| 10 | 2 | Header length | `80` |
| 12 | 2 | Cipher-suite ID | `0x0001` |
| 14 | 2 | Flags | `0`; unknown bits are rejected |
| 16 | 16 | Vault ID | Stable random opaque identifier |
| 32 | 16 | Key ID | Random opaque Keychain-item identifier |
| 48 | 8 | Ciphertext length | Ciphertext including the 16-byte tag |
| 56 | 24 | Nonce | Fresh for this envelope |

Exactly `ciphertext_length` bytes follow the header, followed by EOF. The
associated data is:

```text
"gschrank:vault-envelope:v1\0" || exact_80_header_bytes
```

Authentication uses the exact header representation read from or written to
disk, not a re-encoded structure. Only routing and format information is
public. Profile names, variable names and values, the logical revision, and
the payload schema remain encrypted. File existence, length, timestamps, and
the opaque identifiers remain observable.

## Logical vault and payload codec

One envelope contains the complete logical vault. Every mutation rewrites the
complete vault transactionally. V1 does not create separate encrypted files
per profile.

The plaintext uses a purpose-built, deterministic binary codec rather than a
Rust memory layout or a general-purpose serializer. All integers are unsigned
and big-endian:

```text
u16 schema_version = 1
u16 flags = 0
u64 logical_revision
u32 profile_count

repeated profile_count times:
    u16 profile_name_length
    bytes profile_name
    u32 variable_count

    repeated variable_count times:
        u16 variable_name_length
        bytes variable_name
        u32 value_length
        bytes value
```

Profiles and variables are encoded in strictly increasing byte order. The
decoder rejects duplicates, reordered records, unknown flags, unsupported
versions, invalid UTF-8, invalid profile or variable names, embedded NULs,
impossible lengths, checked-arithmetic overflow, resource-limit violations,
and trailing data. Empty profiles and empty values remain valid. A successful
mutation increments the logical revision using checked arithmetic; revision
exhaustion prevents mutation. The revision aids diagnostics and future
protocols but is not a rollback guarantee.

V1 has these non-configurable hard maxima:

- Complete encrypted envelope: 16 MiB.
- Profiles per vault: 256.
- Variables per profile: 1,024.
- Profile name: the previously decided 64-character ASCII maximum.
- Variable name: 255 UTF-8 bytes, within the previously decided ASCII grammar.
- Individual value: 256 KiB.
- Combined names and values in one profile: 512 KiB.

Lengths and counts are checked against their maxima before allocation. The
codec should operate on validated slices and avoid secret copies where
practical.

## Identifiers and key lookup

Vault creation generates independent random 128-bit vault and key IDs. The
vault ID remains stable across every rewrite. The key ID is represented as
lowercase hexadecimal when used as the exact Keychain account name and changes
only through a future explicit key-rotation protocol. Neither identifier is
secret or user-selectable.

Ordinary reads perform an exact lookup for the header's key ID. They never
create, replace, or select a fallback key when lookup fails. Keeping the key ID
in the envelope permits a future rotation protocol to commit a new key and
vault without prematurely overwriting or deleting the old key.

## Locking and filesystem policy

A stable sidecar such as `vault.lock` is the sole lock target and is never
atomically replaced. Reads hold a shared advisory lock through opening,
authentication, and complete payload validation. Mutations acquire an
exclusive lock before reading and retain it through the entire
read-modify-encrypt-write-sync-replace transaction. Lock acquisition waits by
default. This coordinates cooperating Gschrank processes only; programs that
ignore the protocol are outside the guarantee.

The private data directory is created with mode `0700`. The vault, sidecar
lock, and every temporary replacement file are created with mode `0600`. All
must be owned by the current user. Gschrank rejects unsafe existing ownership
or group/other permissions rather than silently changing them. It also rejects
symlinks and non-regular vault or lock files and uses operations relative to a
validated directory handle where the platform permits. Repair is an explicit
future operation, never a side effect of reading.

## Atomic persistence and crash semantics

A mutation assembles the complete authenticated envelope in secret-aware
memory, then:

1. Creates a randomly named same-directory temporary file atomically with
   no-follow behavior and mode `0600`.
2. Writes only the complete encrypted envelope to that file and flushes any
   userspace buffering.
3. Calls macOS `F_FULLFSYNC`; synchronization failure is an operation error.
4. Atomically renames the temporary file over the live vault while retaining
   the exclusive lock.
5. Invokes the platform-specific post-rename directory-sync hook where
   required, including for the intended Linux implementation.
6. Releases the lock only after all required persistence operations finish.

Gschrank never truncates or modifies the live vault in place and never writes
plaintext to a temporary file. On supported storage, a crash leaves the old or
new complete authenticated envelope. Interruption around the rename can make
the command outcome indeterminate: a reported failure does not prove that the
mutation did not commit, so every retry rereads current state.

V1's durability claim covers local APFS only. Network filesystems,
cloud-synchronized directories, removable media, and untested filesystems are
unsupported vault locations. The envelope remains platform-independent and
the persistence boundary retains the locking and directory-sync seams required
for the planned Linux port.

## Failure and secret-memory contract

All vault read failures are non-destructive. Gschrank never automatically
repairs, resets, initializes over, or replaces an unreadable existing vault.
Authentication failure is generic and does not claim to distinguish a wrong
key, corruption, tampering, or an authenticated-header mismatch. Unsupported
format versions are reported distinctly so an upgrade can be suggested.
Structural errors and diagnostics never reveal decrypted names or values. No
shell output or domain action occurs until authentication and complete payload
validation succeed.

The master key, decrypted payload, parsed values, and generated shell-output
buffers use zeroizing secret containers. Implementations avoid secret clones,
preallocate where practical, and exclude secrets from `Debug`, logs, tracing,
metrics, errors, panic context, and crash-report annotations. Secret material
is dropped as soon as its operation completes. V1 does not add `mlock` and does
not claim complete memory erasure.

## Explicitly unsupported properties

V1 does not provide:

- rollback detection;
- protection from root, hostile same-user processes, live-memory inspection,
  swap, or core dumps;
- protection from a compromised Gschrank binary or malicious dependency;
- secure deletion from SSDs, snapshots, or backups;
- availability against deletion or denied Keychain access;
- concealment of vault existence, size, timestamps, or public opaque IDs;
- coordination with non-cooperating writers; or
- durability guarantees on network, synchronized, or untested filesystems.

Recovery UX, explicit reset, backup restoration, stale-temporary handling, and
key lifecycle are left to
[Decide vault initialization, lifecycle, and recovery behavior](../issues/WF-006-decide-vault-lifecycle.md).
