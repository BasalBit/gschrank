# Resolution: Decide the profile and active-shell domain model

Resolved with Eraldo on 2026-08-05.

Profiles are self-contained named snapshots; v1 has no inheritance, layering,
composition, or merge activation. A shell has zero or one active profile.

Profile names are lowercase ASCII slugs of 1–64 characters matching
`[a-z0-9][a-z0-9._-]{0,63}`. Environment-variable names are case-sensitive,
match `[A-Za-z_][A-Za-z0-9_]*`, and cannot use the reserved `GSCHRANK_`
namespace. Values are valid UTF-8 excluding NUL. Empty values are distinct from
missing values, and empty profiles are valid.

Creating an existing profile fails without mutation. Each profile contains at
most one value for a variable name. `set` is an atomic upsert and reports only
whether it created or updated a name; removing a missing variable fails.

Profile rename is atomic, rejects an existing destination, and updates the
configured startup-profile reference. Existing shells retain their loaded
snapshot. The configured startup profile cannot be deleted until a replacement
is selected. Deleting the current shell's active profile unloads it there;
other running shells retain their copies and must be unloaded or closed.

Activation owns every profile variable by name. It overwrites any colliding
pre-existing shell variable, and switch/unload later unsets that name rather
than restoring a previous value—even if the user manually changed it after
activation. Unrelated names remain untouched.

Profiles load as snapshots. Vault edits affect future activations; existing
shells change only through reload, switch, unload, or deletion of their active
profile. Loading the already-active profile is a transactional reload.

Gschrank exports reserved, names-only bookkeeping such as the active profile
and managed-key manifest so nested shells can replace inherited values. This
metadata never contains secret values. Explicit load, reload, switch, and
unload are transactional from the shell's perspective: failure leaves
variables and metadata unchanged. Automatic startup is governed separately by
[Decide the macOS Keychain backend and startup interaction policy](WF-011-resolution.md)
and fails closed in the newly starting shell. `unload` is an idempotent
current-shell operation and does not change startup configuration.
