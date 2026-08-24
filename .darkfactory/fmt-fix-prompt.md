In /home/fxckcode/projects/agent-guard-proxy, fix ONLY the current rustfmt differences. Do not change behavior, APIs, tests, dependencies, or any file outside this list:
- src/controlled_fetch/redirect.rs
- tests/probe_dkl_24_ssrf_block.rs

Run `cargo fmt` and then verify `cargo fmt -- --check`. Do not commit or push. Return only the command result and changed files.