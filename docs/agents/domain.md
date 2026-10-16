# Domain docs

**Layout: single-context** — one `CONTEXT.md` (optional) at the repo root. There is no separate ADR
tree: an architecture decision lives in the pull request that made it, and its rationale in the
commit message.

## Where things live

- **Root context**: `CONTEXT.md` at repo root if present. For agent-shield, the
  primary doc is `README.md` (purpose, security policy, usage, integration).
- **Domain notes for agents**: this `docs/agents/` directory.

## Reading rules

Agents/skills MUST read `README.md` before touching code (security posture is
load-bearing: SSRF blocking, prompt-injection detection, untrusted-data envelope).

## Writing rules

- English for all repo docs and code (public open-source project).
- `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` and
  `cargo test --locked` must stay green; CI enforces the same gates on every push/PR.