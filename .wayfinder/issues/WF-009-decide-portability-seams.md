---
id: WF-009
title: Decide the portability seams for Bash and Linux
label: wayfinder:grilling
status: closed
assignee: eraldo
parent: WF-001
blocked_by:
  - WF-002
  - WF-003
  - WF-004
  - WF-005
  - WF-011
  - WF-012
resolution: ../comments/WF-009-resolution.md
---

## Question

Which interfaces and stable contracts must separate the platform key provider,
vault persistence, shell code generation, shell configuration editing, and core
profile operations so Bash and Linux can follow without speculative framework
work or a v1 format migration?
