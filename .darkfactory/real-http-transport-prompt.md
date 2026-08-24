Implement the next bounded security slice in /home/fxckcode/projects/agent-guard-proxy: replace the default synthetic transport with a real, minimal HTTP transport over std::net::TcpStream.

Strict TDD:
1. Add failing integration tests FIRST in a new file tests/probe_dkl_24_unit_006_real_http_transport.rs.
2. The tests must start a local TCP listener and verify:
   - A public test address can return a real HTTP response and the transport parses status, headers, and body.
   - The request is sent only after destination IP validation; private/loopback destinations are blocked before the listener receives request bytes.
   - A response body larger than a configured bounded read limit is blocked before delivery.
   - An unsupported URL scheme (https for this initial HTTP-only transport) fails closed with a stable safe reason code. Add a new BlockReason only if needed.
   - The error display never includes the URL, path, headers, body, or hostile payload.
3. Run the focused tests and confirm RED before writing production code.
4. Implement the smallest production change, limited to:
   - src/controlled_fetch/redirect.rs
   - src/controlled_fetch/error.rs only if a new safe reason is required
   - src/controlled_fetch/policy.rs only for explicit bounded read/header limits
   - src/controlled_fetch/mod.rs if wiring/API updates are needed
   - src/controlled_fetch/request.rs if request headers must be serialized safely
   - the new integration test file
   - Cargo.toml only if absolutely necessary; prefer stdlib and do not add an HTTP client dependency.
5. Use TcpStream with connect_timeout/read_timeout/write_timeout. Resolve host and validate every resolved address with validate_connected_ip before connect and before writing the HTTP request. Support only http:// for this slice; reject https:// and other schemes rather than silently downgrading.
6. Parse only bounded headers and body. Never follow redirects outside the existing redirect policy. Preserve the HttpTransport seam for unit mocks.
7. Run: cargo fmt -- --check; cargo test --all-targets; cargo clippy --all-targets --all-features -- -D warnings.

Do not modify src/main.rs, do not commit, push, or touch files outside the allowed list. Do not claim the gateway is complete: report remaining limitations if any. Return a concise summary with RED evidence, changed files, and exact command results.