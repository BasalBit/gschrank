---
id: WF-013
title: Decide whether and how v1 imports existing environment files
label: wayfinder:grilling
status: closed
assignee: eraldo
parent: WF-001
blocked_by:
  - WF-005
  - WF-006
  - WF-008
  - WF-010
resolution: ../comments/WF-013-resolution.md
---

## Question

Should v1 include a `.env` migration helper, and if so which input dialect,
file/stdin boundary, destination-profile behavior, names-only preview,
duplicate and invalid-name policy, overwrite confirmation, value handling, and
transactional failure semantics should it require without introducing a
plaintext-output path?
