Fix ONLY the single Clippy error in /home/fxckcode/projects/agent-guard-proxy/src/controlled_fetch/redirect.rs at the trim_end_matches closure around line 192.

Replace the manual char comparison with the idiomatic equivalent suggested by Clippy (an array pattern such as ['\r', '\n']). Do not change behavior, APIs, tests, dependencies, or any other file. Do not commit or push.

Run only:
- cargo fmt -- --check
- cargo clippy --all-targets --all-features -- -D warnings

Return the exact results and changed file.