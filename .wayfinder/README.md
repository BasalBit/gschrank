# Local Wayfinder tracker

This repository uses Markdown files in `.wayfinder/issues/` as its local issue
tracker. YAML front matter carries tracker state:

- `id` is the stable issue identity.
- `title` is the name used in human-readable references.
- `label` is `wayfinder:map`, `wayfinder:research`, `wayfinder:prototype`,
  `wayfinder:grilling`, or `wayfinder:task`.
- `status` is `open` or `closed`.
- `assignee` is empty until an issue is claimed.
- `parent` identifies the map for child issues.
- `blocked_by` lists issue identities that must be closed first.
- `resolution` points to the resolution comment or research asset after closure.

The frontier is the ordered set of open, unassigned child issues whose
`blocked_by` entries are all closed. Claim an issue by setting `assignee`
before beginning work.

