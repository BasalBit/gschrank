# Resolution: Prototype the Zsh setup and profile-activation contract

Resolved with Eraldo on 2026-08-05.

Eraldo drove the in-memory terminal prototype through setup, successful and
failed startup, explicit switching and failure, reload/unload behavior, binary
upgrade, and uninstall. The resulting behavior matched his expectations without
requested changes.

Setup owns exactly one visibly marked, versioned block in the selected Zsh rc
file. The block contains no secret or encrypted value. It asks the current
`gschrank` binary for a Zsh wrapper on each startup, captures the entire output,
checks producer success, and only then evaluates it. The wrapper disables
tracing locally, intercepts current-shell operations, and delegates ordinary
commands to the executable without passing them through another shell.

Initial setup asks for the startup profile and edits the appropriate
`${ZDOTDIR:-$HOME}/.zshrc` target, with an explicit rc-file override for an
unexported `ZDOTDIR`. It cannot mutate the already-running parent shell, so it
finishes by telling the user to open a new shell or run `exec zsh`. Repeating
setup with identical configuration makes no write. Changing the startup profile
changes only the managed block and does not switch the current shell.

Setup must detect existing function/alias conflicts, malformed or duplicate
managed markers, symlinks, concurrent file changes, and a compiled `.zshrc.zwc`
that could shadow the edit. It stops without writing on ambiguous state. Safe
edits preserve mode, keep a recoverable first-change backup, write and sync a
same-directory temporary file, and replace only after confirming the source did
not change.

The block dynamically requests the wrapper, so a binary upgrade needs no rc
rewrite. The current shell keeps its already-loaded adapter until refreshed or
replaced by a new shell. A new shell replaces inherited managed values with the
configured startup profile. Explicit load/reload/switch failure evaluates
nothing and preserves current state. Automatic startup failure removes inherited
managed names and metadata, reports a concise non-secret warning, and still
opens the shell. A small names-only cleanup fallback in the managed block also
fails closed when the executable is missing or wrapper initialization fails.

`unload` idempotently clears the current shell while leaving startup configured.
Removing shell integration deletes only the managed rc block, clears the current
shell, and removes the current wrapper; it retains the encrypted vault and
Keychain item. Destructive data/key removal belongs to a separate explicit
purge lifecycle.

Prototype primary source:
[Gschrank Zsh contract prototype](/private/tmp/gschrank-prototype-zsh/PROTOTYPE.md)
and [illustrative managed block](/private/tmp/gschrank-prototype-zsh/prototype.zsh)
on branch `prototype/zsh-setup-activation-contract`, commit `f49273c`.

