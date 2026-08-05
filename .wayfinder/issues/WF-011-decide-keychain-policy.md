---
id: WF-011
title: Decide the macOS Keychain backend and startup interaction policy
label: wayfinder:grilling
status: closed
assignee: eraldo
parent: WF-001
blocked_by: []
resolution: ../comments/WF-011-resolution.md
---

## Question

Which macOS Keychain implementation and Rust integration should v1 adopt, what
stable service/account/key identity should it publish, how should binary
upgrades preserve access, and should automatic interactive Zsh startup allow an
unlock prompt or fail fast when Keychain interaction is required?
