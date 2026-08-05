# Resolution: Decide the macOS Keychain backend and startup interaction policy

Resolved with Eraldo on 2026-08-05.

V1 uses the current user's file-based login Keychain. It stores the vault
master key as a non-synchronizing generic-password item and implements native
access through the `security-framework` crate behind an application-owned
`MacOsKeychainProvider` adapter. The adapter must use exact queries and
create-only insertion rather than an upserting convenience API. The dependency
version and its maintenance/security posture must be reviewed before release.

The permanent item identity is:

```text
class   = generic password
service = com.basalbit.gschrank.vault-key
account = <random 128-bit key ID encoded as lowercase hex>
```

The same non-secret key ID appears in the vault envelope. The secret item data
is exactly 32 cryptographically random bytes stored as opaque binary; any other
length is invalid key material. The service string is a permanent compatibility
identifier. Binary upgrades preserve the exact service/account identity and
must never recreate or overwrite the item merely because access failed.

V1 accepts that macOS may request one-time reauthorization after a binary
upgrade. Stable Developer ID signing is not a v1 requirement. Gschrank uses the
file-Keychain item's default restricted access behavior and does not install a
custom broadened trust list. Requiring Touch ID or user presence on every read
is deferred as a possible post-v1 hardening mode because it conflicts with
automatic shell startup.

The provider interface offers `load`, create-only `store_new`, and explicitly
destructive `delete`; it has no ordinary key-overwrite operation. Native
Keychain results translate immediately into portable semantic categories:
`NotFound`, `AlreadyExists`, `UserCancelled`, `AuthenticationFailed`,
`InteractionRequired`, `PermissionDenied`, `Unavailable`,
`InvalidKeyMaterial`, and `BackendFailure`. The original `OSStatus` may remain
as non-secret diagnostic context but never controls portable core policy.

Each provider call receives an explicit interaction policy. Interactive setup,
editing, and automatic interactive Zsh startup use `AllowPrompt`; noninteractive
automation uses `FailFast` and returns `InteractionRequired` instead of opening
a GUI prompt.

Normal startup remains silent while the login Keychain is unlocked and the
binary is trusted. If authorization is required, macOS may prompt. Cancellation
or any load failure must not prevent Zsh from opening. Automatic startup is a
deliberate fail-closed exception to ordinary transactional switching: the new
shell clears inherited Gschrank-managed variables and metadata, then emits a
non-secret warning. Explicit load, reload, and switch failures preserve the
current profile.

