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
- [x] M1 — Remove the unsupported Wayfinding instructions from `docs/agents/issue-tracker.md`.
- [ ] M2 — Document `probes/fixture_server.py` as a manual-only localhost utility in `probes/README.md`.
- [ ] M3 — Hand the owner the exact `AGENTS.md` replacements; do not edit this guarded file.

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
- Engram mirror is pending: the memory backend does not recognize this repository as a project; do not guess a project key.
- Next step: delegated M1/M2, then structural readback and one local work-unit commit per completed task.
