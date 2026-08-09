# Resolution: Prototype the v1 CLI and onboarding journey

Resolved with Eraldo on 2026-08-06.

Eraldo drove the throwaway Rust terminal prototype through the guided command
journey and reported that everything felt good. The prototype covered explicit
initialization, profile creation and editing, names-only inspection, startup
selection, current-shell activation, Keychain failure, fail-closed shell
startup, encrypted backup, fresh-vault rebuild, recovery metadata, reset,
restore, and purge.

## Guided configuration

`gschrank config` is the primary interactive onboarding command. With no live
vault it:

1. explains that no vault exists and asks permission to run explicit
   initialization;
2. creates an empty encrypted vault and Keychain key through the normal `init`
   lifecycle;
3. asks for the first profile name;
4. accepts zero or more variable names and obtains each value through a
   no-echo prompt;
5. asks whether that profile should load in every new Zsh shell;
6. installs the managed Zsh integration block; and
7. explains that the child process cannot mutate the current parent shell, so
   the user must open a new shell or run `exec zsh`.

The wizard announces every state-changing phase. Cancellation before
initialization changes nothing. Cancellation after initialization may leave a
valid empty vault, which repeated `config` resumes without recreating. With an
existing healthy vault, `config` authenticates it first and configures a new or
existing profile and startup selection without reinitializing. It never asks
for a secret value until vault access, profile name, and variable name have
validated.

`gschrank init` remains the smaller explicit operation that creates only an
empty vault. Repeating it against a healthy vault is the previously decided
authenticated no-op.

## V1 command surface

The accepted production command grammar is:

```text
gschrank config
gschrank init

gschrank profile create <profile>
gschrank profile rename <old> <new>
gschrank profile delete <profile>
gschrank profile list
gschrank profile inspect <profile>

gschrank set <profile> <variable> [--stdin]
gschrank remove <profile> <variable>

gschrank startup set <profile>
gschrank startup off

gschrank shell uninstall

gschrank load <profile>
gschrank reload
gschrank unload

gschrank status
gschrank doctor

gschrank backup <destination>
gschrank restore <source>
gschrank reset
gschrank rebuild

gschrank recovery list
gschrank recovery restore <bundle-id>
gschrank recovery purge <bundle-id>

gschrank purge
```

`new-shell` and `fault` were prototype controls only and are not production
commands.

`set` never accepts a secret value as a positional argument or ordinary
option. Without `--stdin`, it requires an interactive terminal and reads a
value using a no-echo prompt. `--stdin` is the deliberate noninteractive path:
it reads the complete value from standard input through EOF and never falls
back to arguments. Callers are responsible for avoiding newline-producing
shell helpers when a trailing newline is not part of the intended value.
Invalid vault/profile/name state is rejected before reading standard input or
opening the hidden prompt. An empty input remains a valid empty value.

The CLI must reject ambiguous simultaneous TTY/stdin modes and never echo,
confirm by printing, log, or include the value or its length in success or
error output. `set` reports only whether the variable name was created or
updated. `remove` reports only the removed name.

## Profiles, status, and shell behavior

`profile list` prints profile names only. `profile inspect` prints only the
selected profile name and its variable names. Neither decrypts values for
display, prints value lengths, or offers a plaintext-output flag.

`profile rename` atomically updates startup selection while existing shells
retain their loaded snapshot. `profile delete` enforces the previously decided
startup-profile guard and unloads the invoking shell if that profile is active
there. `startup set` and `startup off` affect future shells only and never
silently switch the current shell.

`load`, `reload`, and `unload` are current-shell operations intercepted by the
installed Zsh wrapper. Successful load/reload transactionally replaces the
complete managed snapshot. Failure leaves the current shell unchanged.
`unload` is idempotent and leaves startup selection intact. When these words
reach the executable directly rather than through shell integration, the CLI
does not pretend it can mutate its parent; it returns an actionable instruction
to install/refresh the wrapper or evaluate the validated shell protocol.

`status` is names-only and reports the safe lifecycle state, vault readiness,
shell-integration state, startup profile, current-shell active profile and
managed names when available, profile names, and variable names. When vault
access fails, it reports only safe lifecycle and shell metadata and does not
show cached profile/variable names. `doctor` reports safe failure stages and
remediation guidance under the already decided diagnostic contract.

Automatic startup remains separate from explicit load: it replaces inherited
managed values with the configured profile on success and clears inherited
managed names on failure while allowing Zsh to open.

## Recovery journey

`backup` and `restore` use user-selected filesystem paths and the encrypted
backup contract. Restore uses typed confirmation before displacing a live
vault into internal recovery. `reset` uses typed `RESET` confirmation and
creates a new empty vault while retaining the old recovery pair. `rebuild`
uses typed `REBUILD` confirmation and copies all profiles under a new vault
identity and master key while retaining the old pair.

`recovery list` shows bundle ID, reason, creation time, opaque vault/key IDs,
and authentication status only. `recovery restore` uses typed confirmation and
preserves the displaced live vault as another recovery bundle. `recovery
purge` warns about external backups and uses typed `PURGE` confirmation.

Full `purge` uses typed `PURGE` confirmation, has no unattended force flag in
v1, removes future shell integration and internal recovery state, and explains
that other live processes cannot be cleared. User-directed external backup
files remain in place even though deleted Keychain keys may make them
unusable.

Exact output styling and machine-readable exit-code conventions remain subject
to the final no-leak security and acceptance contract; the interaction and
information boundaries above are fixed.

Prototype primary source:
[Gschrank v1 CLI journey prototype](/private/tmp/gschrank-prototype-cli/PROTOTYPE.md)
on branch `prototype/cli-onboarding-journey`, commit `cdf47dc`.
