# Resolution: Decide whether and how v1 imports existing environment files

Resolved with Eraldo on 2026-08-07.

## V1 command and input boundary

V1 includes a narrowly scoped dotenv migration command with this binary-name-
independent grammar:

```text
<executable> import dotenv <profile> [--dry-run] [--replace-existing]
```

The destination profile must already exist; import never creates, selects,
loads, or configures a startup profile. The dotenv document is read only from
standard input. Import has no source-path argument and no `--stdin` flag,
because stdin is its sole input mode. Terminal stdin is rejected immediately
with usage guidance; the caller must deliberately redirect or pipe a
non-terminal stream.

This does not change `set`: `set` retains `--stdin` because that flag selects
its noninteractive input mode instead of its default hidden-terminal prompt.
Across the CLI, `--stdin` is used only where it distinguishes genuine input
modes.

## Additive merge and collision authorization

Import performs an additive upsert into the existing profile:

- imported names absent from the profile are added;
- imported names already present are replaced only when
  `--replace-existing` was supplied; and
- existing profile names absent from the input remain untouched.

Without `--replace-existing`, any collision refuses the complete import and
reports only the colliding variable names. There is no partial add of the
non-colliding entries. The explicit flag is sufficient authorization for all
collisions; import does not add an interactive confirmation prompt.

`--dry-run` authenticates the vault, reads and fully validates the input, and
reports only the names that would be added and the names that collide. It
never mutates the vault and never prints values. A dry run is advisory: a
later real import rereads its input and revalidates the latest vault state.

## Strict dotenv dialect

Gschrank parses a documented data-only subset in-process. It never sources the
document, invokes a shell, or performs variable expansion, command
substitution, includes, or external evaluation.

The accepted document is UTF-8 with an optional UTF-8 BOM at the very
beginning. It accepts LF and CRLF source line endings; physical source line
breaks inside multiline quoted values normalize to LF. A bare carriage return
is invalid. A literal carriage return may be written as `\r` inside a
double-quoted value.

The grammar accepts:

- blank lines and comment lines after optional horizontal whitespace;
- assignments in the form `NAME=VALUE`;
- an optional `export` keyword followed by whitespace before an assignment;
- unquoted, single-quoted, and double-quoted values; and
- physical multiline content inside single- or double-quoted values.

Unquoted values have surrounding horizontal whitespace removed. Outside
quotes, `#` begins an inline comment only when preceded by horizontal
whitespace. Unquoted values have no escape or expansion processing.

Single-quoted content is literal except for source-line normalization; it has
no escape processing. Double-quoted content recognizes exactly `\\`, `\"`,
`\n`, `\r`, and `\t`. An unknown escape is invalid. Dollar signs, `${...}`,
`$(...)`, and backticks remain literal data and are never interpreted. After
a closing quote, only horizontal whitespace or a comment is accepted.
Unterminated quotes and any unsupported syntax reject the document.

Decoded values continue to obey the profile model: valid UTF-8, no NUL, and
empty values distinct from missing values.

## Rejection and resource limits

A variable name may appear at most once in one input document. A duplicate is
an error even if both decoded values would be identical; import has no first-
wins or last-wins behavior.

The complete import is rejected for any duplicate, malformed syntax, invalid
UTF-8, NUL, unsupported escape, invalid environment name, reserved
`GSCHRANK_` name, overflow, or resource-limit violation. Errors may identify a
safe line number, variable name, and semantic category, but never a source
line, value, excerpt, per-value length, hash, fingerprint, or equality result.

Raw stdin is capped at a non-configurable 2 MiB and is read incrementally into
bounded zeroizing storage. The parser reports only that the documented input
limit was exceeded, not the observed size. The decoded result must also obey
the existing final-profile limits: at most 1,024 variables, 256 KiB per value,
and 512 KiB of combined names and values. Because import is additive, these
limits are checked against the complete resulting profile, including preserved
existing entries.

An empty or comments-only document is a valid successful no-op. It reports
that no variables were found, performs no vault write, and does not increment
the logical revision.

## Transaction and failure behavior

Import uses two phases so it validates before consuming secret input without
holding an exclusive lock while waiting for stdin:

1. Authenticate and completely validate the vault and destination profile.
2. Read and parse the bounded document into zeroizing memory.
3. Acquire the exclusive vault transaction, reopen and authenticate the latest
   vault, and revalidate the profile, collisions, limits, and mutation plan.
4. Apply the complete additive merge through one encrypted atomic vault
   replacement.

Any pre-commit failure changes nothing. Concurrent profile deletion, mutation,
new collision, or capacity change is detected against the latest state rather
than silently overwritten. Persistence exposes the complete old authenticated
vault or the complete new authenticated vault; an unresolvable final commit
ambiguity uses the existing indeterminate outcome and retry contract. Parsed
values and all derived secret buffers are zeroized on success, failure,
cancellation, and unwind to the extent guaranteed by the accepted memory
contract.

Public stdout and stderr remain safe-metadata-only. A successful nonempty
import may report created and replaced names and counts but never values. V1
adds no plaintext export counterpart.

## Plaintext-source responsibility

Because stdin deliberately hides the source path, Gschrank never guesses,
deletes, truncates, renames, or changes permissions on an original file. V1
has no `--delete-source` option. After a successful nonempty real import, it
warns safely on stderr that, if the input came from a plaintext file, that file
still exists and must be secured or removed separately after verification. It
does not infer or print a filename. Dry runs and empty no-op imports do not
print this warning.

The release-blocking no-leak suite covers every parser form and rejection,
multiline and line-ending behavior, duplicate and collision handling, preview,
empty input, concurrency, fault-injected atomic commit, zeroization paths, and
canary scans of public output and every Gschrank-owned file.
