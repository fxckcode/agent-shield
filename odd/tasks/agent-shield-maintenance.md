# Agent Shield maintenance cleanup

## Objective
Resolve the three maintenance findings raised by the owner without bypassing the instruction-file approval guard or inventing a GitHub label.

## Problem and rationale
`AGENTS.md` has stale architecture and gate instructions, but writes to instruction files have been repeatedly refused by the approval guard. `probes/fixture_server.py` is a standalone localhost HTTP fixture with no automated references, while the issue-tracker guide documents a `/wayfinder` label workflow that has no repository artifact or matching GitHub label. Keep the useful fixture and make its manual-only status clear; remove unsupported Wayfinding operations; leave the guarded AGENTS.md change pending for the owner.

## Scope authorized
- `probes/README.md` — create concise manual-use documentation for `fixture_server.py`.
- `docs/agents/issue-tracker.md` — remove the unsupported Wayfinding operations section only.
- `AGENTS.md` — no agent write; provide exact replacement text to the owner because the approval guard refused prior edits.

## Tasks
- [x] M1 — Remove the unsupported Wayfinding instructions from `docs/agents/issue-tracker.md` (commit `d10e68bd34419ae73b3aaf5ca2031f31880da90a`).
- [x] M2 — Document `probes/fixture_server.py` as a manual-only localhost utility in `probes/README.md`.
- [ ] M3 — Hand the owner the exact `AGENTS.md` replacements; do not edit this guarded file. This remains blocked for human application.

## Acceptance criteria
- `docs/agents/issue-tracker.md` no longer promises a `/wayfinder` label workflow that the repository and GitHub do not provide.
- `probes/README.md` states that current probes/CI do not use the fixture, explains how to run it, its default port `18091`, loopback-only binding, and response; if discussing `agent-shield fetch`, clearly warn that private/loopback access is blocked by default and the override is test-only.
- The existing fixture remains unchanged.
- `AGENTS.md` remains untouched; its required replacement text is reported to the owner.
- No tests are required for these passive documentation changes; verify by structural readback and run the claim auditor once.

## Routing and risk
- M1 + M2: one delegated writer because this is a two-file documentation change that requires contextual reading; risk tier passive. Allowed files are only those named under Scope authorized, excluding `AGENTS.md`.
- M3: parent-only handoff; editing is prohibited by the repeated approval guard.
- Forecast: approximately 35 authored lines; delivery strategy `single-pr` is not invoked because no PR or public write is authorized.

## Verification / progress
- Initial inspection at `59bb44f2ea80aceb9ed29911474d60e83e272c81`; working tree was clean; latest CI `38927847139` succeeded.
- CodeGraph index/CLI are unavailable on this host; used bounded Git/repository inspection instead.
- A read-only consult with `mattpocock-expert` recommended documenting the fixture as a manual utility and removing the unsupported Wayfinding section.
- M1 completed as passive documentation; `git diff --check` passed and structural readback confirmed only the unsupported Wayfinding section was removed. Commit: `d10e68bd34419ae73b3aaf5ca2031f31880da90a`.
- M2 completed as passive documentation; `git diff --check` passed and structural readback confirmed the manual invocation, default port, loopback binding, GET response, and that current probes/CI do not use the fixture. Commit: `fa454fbbbcf7919db85129a9421bd891e6aad6e2`.
- The writer ran the claim auditor once; it returned code 0 and six review items. Two AGENTS.md probe paths are prefix-only false positives, two CONTEXT.md references are optional, and the auditor currently omits nested `probes/README.md`; it therefore still flags the standalone fixture as undocumented. The actual README was read back and documents it.
- `AGENTS.md` remains untouched. Engram mirror is pending: the memory backend does not recognize this repository as a project; do not guess a project key.
- Owner handoff for M3 (apply these lines through the approval gate):
  - Replace the ADR sentence with:
    ```text
    Architecture decisions are recorded in the pull request that made them. See `docs/agents/domain.md`.
    ```
  - Replace the gates bullet with:
    ```text
    - Gates: `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
      `cargo test --locked`; CI also runs `probes/checklist.py`, `probes/e2e_full.py`,
      `probes/e2e_smoke.py`, and `probes/e2e_proxy_server.py`.
    ```
- Next step: owner applies the AGENTS.md replacement through the approval gate; no PR or push was made.
