---
id: WF-002
title: Research the macOS Keychain key-provider contract
label: wayfinder:research
status: closed
assignee: research-agent-keychain
parent: WF-001
blocked_by: []
resolution: ../comments/WF-002-resolution.md
---

## Question

What guarantees and constraints do macOS Keychain APIs and viable maintained
Rust integrations impose on generating, storing, retrieving, and deleting
Gschrank's random master key during Zsh startup, including prompts, access
control, stable service/account identifiers, failure states, and the seam a
future Linux key provider will need?
