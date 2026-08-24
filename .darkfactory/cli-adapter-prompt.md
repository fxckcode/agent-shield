Implement the final bounded CLI adapter in /home/fxckcode/projects/agent-guard-proxy.

Goal: replace the current src/main.rs Hello World scaffold with a minimal executable CLI that exposes the verified controlled-fetch library.

Strict TDD:
1. Add failing integration tests FIRST in tests/probe_dkl_24_unit_007_cli_smoke.rs using std::process::Command and env!("CARGO_BIN_EXE_agent-guard-proxy"). Tests must verify:
   - `--help` exits 0 and prints usage containing `fetch`.
   - `fetch https://example.com` exits nonzero and prints JSON containing only the safe reason code `UNSUPPORTED_SCHEME`, a correlation id, and no URL/host/path/query.
   - `fetch http://127.0.0.1:9/secret?token=redacted-test-value` exits nonzero and prints JSON containing `SSRF_PRIVATE_IP`, a correlation id, and none of the URL/host/path/query/token.
   - Missing command/argument exits nonzero and prints safe usage/error output without panic.
2. Run only the new focused test and confirm RED before implementing production code.
3. Implement only:
   - src/main.rs
   - tests/probe_dkl_24_unit_007_cli_smoke.rs
   Do not modify the controlled_fetch library, Cargo.toml, dependencies, or any other file.
4. CLI contract:
   - `agent-guard-proxy --help` prints concise usage and exits 0.
   - `agent-guard-proxy fetch <url>` uses FetchRequest::new and FetchPolicy::default, calls fetch_with_policy, and exits 0 on allowed content or 1 on any blocked/error result.
   - Success output is JSON with `status`, `correlation_id` if available from the envelope, `classification`, and escaped body. Do not claim content is trusted.
   - Blocked output is JSON with `status: "blocked"`, `reason_code`, and `correlation_id`; never include URL, host, path, query, headers, or body. Do not print Rust Debug output or panic traces.
   - Invalid CLI input prints safe JSON or usage to stderr and exits 2.
   - Use only stdlib/manual JSON escaping if needed; do not add dependencies.
   - Keep user-facing artifact strings in English, identifiers/comments in English.
5. Run: cargo fmt -- --check; cargo test --all-targets; cargo clippy --all-targets --all-features -- -D warnings.
6. Do not commit or push. Report exact RED evidence, changed files, and exact GREEN results. Do not claim a production daemon/server; this is a minimal CLI adapter only.