Fix only the confirmed deadlock in /home/fxckcode/projects/agent-guard-proxy.

Allowed files:
- src/controlled_fetch/redirect.rs
- tests/probe_dkl_24_unit_006_real_http_transport.rs

Root cause:
- real_http_request() always calls validate_connected_ip for resolved addresses, even when FetchPolicy.block_private_ips is false. The local integration tests intentionally disable that policy to use 127.0.0.1, so the client never connects and the server thread waits forever.

Required fix:
- Only apply the resolved-address validate_connected_ip checks when policy.block_private_ips is true. When false, retain the explicit opt-out for local/test transport.
- Keep validation before connect and before writing request bytes whenever the policy is enabled.
- Remove unused BlockReason and FetchError imports from the unit-006 integration probe if they remain unused.
- Do not change any other behavior, API, dependency, or file.

Run only these focused checks after the fix:
- cargo fmt -- --check
- cargo test --test probe_dkl_24_unit_006_real_http_transport real_transport_parses_status_headers_and_body -- --nocapture
- cargo test --test probe_dkl_24_unit_006_real_http_transport oversized_body_blocked_before_delivery -- --nocapture
Then report exact results. Do not run the full suite, commit, or push.