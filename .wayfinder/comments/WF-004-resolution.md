# Resolution: Research safe Zsh environment mutation and startup semantics

Resolved on 2026-08-05 by `research-agent-zsh`.

A standalone executable cannot mutate its parent Zsh environment. Gschrank
therefore needs a same-named Zsh function that delegates ordinary commands and
captures secret-bearing machine output completely before evaluating it only on
successful producer exit. The emitter must use a closed, tested grammar; the
wrapper must localize shell options and disable tracing. Exported names-only
metadata lets nested shells replace inherited managed variables.

Setup must respect `ZDOTDIR`, function conflicts, symlinks, compiled `.zwc`
files, and idempotent atomic managed-block editing. Zsh source generation and
startup policy belong behind a shell-adapter boundary for later Bash support.

Research asset:
[Safe Zsh environment mutation and startup semantics](/private/tmp/gschrank-research-zsh/docs/research/zsh-environment-mutation.md)
on branch `research/zsh-environment-semantics`, commit `c225e94`.

