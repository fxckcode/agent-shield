# Domain docs

**Layout: single-context** — one `CONTEXT.md` (optional) + `docs/adr/` at the repo root.

## Where things live

- **Root context**: `CONTEXT.md` at repo root if present. For agent-shield, the
  primary doc is `README.md` (purpose, security policy, usage, integration).
- **ADRs**: `docs/adr/` for architecture decision records.

## Reading rules

Agents/skills MUST read `README.md` before touching code (security posture is
load-bearing: SSRF blocking, prompt-injection detection, untrusted-data envelope).

## Writing rules

- English for all repo docs and code (public open-source project).
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` must stay green;
  CI enforces the same gates on every push/PR.