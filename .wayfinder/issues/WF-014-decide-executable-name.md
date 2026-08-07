---
id: WF-014
title: Decide the v1 executable name and command compatibility strategy
label: wayfinder:grilling
status: closed
assignee: eraldo
parent: WF-001
blocked_by:
  - WF-008
  - WF-009
resolution: ../comments/WF-014-resolution.md
---

## Question

Should v1 ship only as the short `gs` executable despite its established
collision with Ghostscript, retain `gschrank` as the canonical executable with
an optional short alias, or use another short spelling—and what must install,
collision detection, documentation, shell integration, compatibility, and
upgrade behavior guarantee once that spelling is chosen?
