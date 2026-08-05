# Resolution: Research the encrypted vault security envelope

Resolved on 2026-08-05 by `research-agent-vault`.

The research recommends a versioned binary envelope using XChaCha20-Poly1305,
fresh random 24-byte nonces, exact-header associated data, and zeroizing secret
containers. Persistence should use a stable sidecar lock, a same-directory
mode-`0600` temporary file, synchronization, and atomic replacement inside a
mode-`0700` directory. The format can detect modification but cannot prevent
rollback or eliminate plaintext memory exposure.

Cipher policy, public-header details, payload codec and granularity, resource
limits, and the exact durability contract remain product/technical decisions.

Research asset:
[Encrypted vault security envelope](/private/tmp/gschrank-research-vault/docs/research/encrypted-vault-security-envelope.md)
on branch `research/encrypted-vault-envelope`, commit `e9c7457`.

