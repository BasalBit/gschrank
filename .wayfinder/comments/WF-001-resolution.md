# Resolution: Find the way to an implementation-ready Gschrank v1 specification

Destination reached with Eraldo on 2026-08-07.

Every child research, prototype, and decision ticket is closed, and the map has
no remaining in-scope fog. The canonical
[Gschrank v1 specification map](../issues/WF-001-gschrank-v1-specification.md)
and its linked resolutions now define an implementation-ready Rust CLI for
macOS/Zsh, including:

- the local threat model and no-leak acceptance gate;
- profile, shell-ownership, startup, and replacement semantics;
- the macOS Keychain provider and authenticated encrypted-vault formats;
- transactional persistence, lifecycle, backup, recovery, reset, rebuild, and
  purge behavior;
- the production command grammar, onboarding journey, dotenv import, and
  canonical `gschrank` plus optional `gsch` interaction model;
- the Zsh wrapper and configuration-editing contracts; and
- narrow portability seams for later Linux/Bash adapters.

The map is planning-only. Closing it records that no product or technical
decision currently blocks implementation; it does not claim that the CLI has
been implemented, packaged, audited, or released. Work beyond the map's
explicit destination remains in its Out of scope section.
