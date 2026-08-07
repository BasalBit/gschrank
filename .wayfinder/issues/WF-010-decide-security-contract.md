---
id: WF-010
title: Decide the no-leak security and acceptance contract
label: wayfinder:grilling
status: closed
assignee: eraldo
parent: WF-001
blocked_by:
  - WF-003
  - WF-006
  - WF-007
  - WF-008
  - WF-009
  - WF-011
  - WF-012
resolution: ../comments/WF-010-resolution.md
---

## Question

What explicit security invariants, redaction rules, permissions, failure-mode
requirements, tests, and acceptance scenarios must the v1 specification impose
so secrets do not leak through dotfiles, CLI arguments, normal output, logs,
temporary files, crashes, backups, or routine agent inspection?
