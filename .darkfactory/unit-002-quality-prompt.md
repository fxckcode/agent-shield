Fix ONLY the current quality-gate failures in /home/fxckcode/projects/agent-guard-proxy for work unit DKL-24-unit-002.

Allowed files:
- src/controlled_fetch/redirect.rs
- tests/probe_dkl_24_unit_002_redirect_policy.rs only if cargo fmt requires it

Current failures:
- cargo clippy --all-targets --all-features -- -D warnings reports field-reassign-with-default at redirect.rs lines around the tests that set policy.max_redirects = 3. Use struct-update initialization without changing test behavior.
- cargo fmt -- --check reports formatting differences in redirect.rs and may format the probe file.

Do not change production behavior, public APIs, dependencies, acceptance criteria, or files outside the allowed list. Run cargo fmt, then verify:
- cargo fmt -- --check
- cargo test --all-targets
- cargo clippy --all-targets --all-features -- -D warnings
Do not commit or push. Return changed files and exact results.