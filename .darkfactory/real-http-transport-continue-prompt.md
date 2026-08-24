Continue the already-started real HTTP transport slice in /home/fxckcode/projects/agent-guard-proxy.

Context already verified:
- The new test file tests/probe_dkl_24_unit_006_real_http_transport.rs exists.
- RED was confirmed: https:// and ftp:// do not return UNSUPPORTED_SCHEME, and the local-server tests hang because SocketValidatingTransport still uses synthetic response logic.
- Do not rerun the full focused test suite before implementing; the existing synthetic transport can hang the local-server tests.

Implement the smallest production fix, limited to:
- src/controlled_fetch/redirect.rs
- src/controlled_fetch/error.rs if needed
- src/controlled_fetch/policy.rs if needed
- src/controlled_fetch/mod.rs if needed
- src/controlled_fetch/request.rs if needed
- tests/probe_dkl_24_unit_006_real_http_transport.rs only if a test fixture needs a bounded fix
- Cargo.toml only if absolutely necessary; prefer stdlib.

Requirements:
1. SocketValidatingTransport must perform a real HTTP/1.1 request using std::net::TcpStream, not synthetic responses.
2. Support only http:// in this slice. Reject https://, ftp://, and other schemes before DNS/network with a stable UNSUPPORTED_SCHEME reason code; never leak URL data.
3. Parse host/port/path with url::Url. Resolve all addresses, validate each with validate_connected_ip before connecting or writing request bytes. Use connect_timeout, read_timeout, and write_timeout.
4. Send a bounded GET request with safe Host header and request headers from FetchRequest. Do not serialize CR/LF-containing header names or values; fail closed if encountered.
5. Read bounded response headers and body. Reject Content-Length above policy.max_body_size before reading the body. Do not allocate unbounded buffers. Preserve existing content_filter and redirect policy behavior.
6. Keep HttpTransport as the test seam. Do not alter public security semantics outside this slice.
7. Run only bounded checks after implementation: cargo fmt -- --check; cargo test --all-targets; cargo clippy --all-targets --all-features -- -D warnings. Do not run a test command piped through head or tail. Do not commit or push.
8. Report limitations honestly. Do not touch src/main.rs.

Return concise JSON-like summary with changed files and exact results.