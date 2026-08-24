Fix only the existing Rust quality-gate failures in /home/fxckcode/projects/agent-guard-proxy.

Scope: modify only these files if needed:
- src/controlled_fetch/injection_detector.rs
- src/controlled_fetch/content_filter.rs
- src/controlled_fetch/envelope.rs
- src/controlled_fetch/ip_validator.rs
- src/controlled_fetch/mod.rs
- src/controlled_fetch/redirect.rs

Current failures:
1. cargo clippy --all-targets --all-features -- -D warnings reports clippy::wildcard-in-or-patterns for `"v1" | _` in injection_detector.rs. Preserve the existing fallback behavior while removing the lint.
2. Clippy reports field-reassign-with-default in the content_filter test and injection_detector test. Rewrite those test initializers without changing behavior.
3. cargo fmt -- --check reports formatting differences in the files above. Run cargo fmt after the minimal fixes.

Do not add features, change the public API, change security behavior, add dependencies, commit, push, or touch files outside the listed scope. Run and report exactly:
- cargo fmt -- --check
- cargo test --all-targets
- cargo clippy --all-targets --all-features -- -D warnings

Return a concise summary with changed files and command results.