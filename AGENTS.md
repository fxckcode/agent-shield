# AGENTS.md — agent-shield

Secure fetch gateway and forward proxy for agent CLIs. Blocks phishing/SSRF,
revalidates redirects, filters dangerous content, and wraps external content in
an untrusted-data envelope. Also exposes an HTTP forward proxy (`serve`) that
validates destinations before opening tunnels.

## Agent skills

### Issue tracker

Issues and PRDs live as **GitHub issues** in this repo. Use the `gh` CLI.
See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical five-role labels: `needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context. Read `README.md` first (purpose, security policy, integration);
ADRs in `docs/adr/`. See `docs/agents/domain.md`.

## Engineering process (Matt Pocock skills)

Use the aihero.dev flow for features: **grill-with-docs** → **to-spec** →
**to-tickets** → **implement** → **code-review**. Shaping (`wayfinder`,
`prototype`, `research`) for open questions; upkeep (`improve-codebase-architecture`,
`diagnosing-bugs`, `triage`, `wizard`) for maintenance; reference skills
(`codebase-design`, `domain-modeling`, `grilling`, `tdd`) underpin the flow.

## Working rules

- Rust, edition 2021, English only.
- Gates: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` (75 tests),
  plus E2E harnesses in `probes/` (`e2e_full.py`, `e2e_proxy_server.py`).
- The forward-proxy server listens on `127.0.0.1:<port>` (`serve --port`, default 8087);
  `AGP_ALLOW_PRIVATE=1` is the testing-only escape (never in production).
- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- The human always merges PRs.