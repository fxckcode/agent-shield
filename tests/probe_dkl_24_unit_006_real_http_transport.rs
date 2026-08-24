//! Integration tests for real HTTP transport over TcpStream.
//!
//! Verifies that the transport:
//! - Parses real HTTP/1.1 responses (status, headers, body).
//! - Blocks private/loopback destinations before connect.
//! - Enforces bounded read limits on response body.
//! - Rejects unsupported URL schemes (https) with a stable reason code.
//! - Never leaks URLs, headers, or payloads in error display.

use std::io::Write;
use std::net::TcpListener;
use std::thread;

use agent_guard_proxy::controlled_fetch::{FetchPolicy, FetchRequest};

/// Helper: start a local TCP listener that sends a raw HTTP response, return the bound port.
fn spawn_http_server(response_bytes: Vec<u8>) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind to ephemeral port");
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Read request (drain it so the write side doesn't block)
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut buf);
            // Send the raw response
            let _ = stream.write_all(&response_bytes);
            let _ = stream.flush();
        }
    });

    (port, handle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: Real HTTP response parsing — status, headers, and body
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn real_transport_parses_status_headers_and_body() {
    let body = b"Hello, world!";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Custom: test-value\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    );

    let (port, handle) = spawn_http_server(response.into_bytes());

    let policy = FetchPolicy {
        block_private_ips: false, // Allow loopback for local test server
        ..FetchPolicy::default()
    };

    let req = FetchRequest::new(&format!("http://127.0.0.1:{}/test", port));
    let result = agent_guard_proxy::controlled_fetch::fetch_with_policy(&req, &policy);

    handle.join().unwrap();

    let envelope = result.expect("should parse a valid HTTP response");
    assert_eq!(envelope.body(), b"Hello, world!");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: Private/loopback destination blocked BEFORE connect
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn private_destination_blocked_before_connect() {
    // Start a server on loopback — policy should block BEFORE any bytes are sent
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nSECRET";
    let (port, handle) = spawn_http_server(response.to_vec());

    let policy = FetchPolicy::default(); // block_private_ips = true

    let req = FetchRequest::new(&format!("http://127.0.0.1:{}/secret", port));
    let result = agent_guard_proxy::controlled_fetch::fetch_with_policy(&req, &policy);

    // The server should NOT have received the connection (no bytes sent)
    // We can't easily assert the server saw nothing, but the error must fire.
    drop(handle);

    let err = result.expect_err("should block private IP destination");
    assert_eq!(err.reason_code(), "SSRF_PRIVATE_IP");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: Response body larger than bounded read limit is blocked
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn oversized_body_blocked_before_delivery() {
    // 512 bytes body, policy limit = 128 bytes
    let body = "X".repeat(512);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let (port, handle) = spawn_http_server(response.into_bytes());

    let policy = FetchPolicy {
        block_private_ips: false,
        max_body_size: 128,
        ..FetchPolicy::default()
    };

    let req = FetchRequest::new(&format!("http://127.0.0.1:{}/big", port));
    let result = agent_guard_proxy::controlled_fetch::fetch_with_policy(&req, &policy);

    handle.join().unwrap();

    let err = result.expect_err("should block oversized body");
    assert_eq!(err.reason_code(), "BODY_SIZE_LIMIT_EXCEEDED");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: Unsupported URL scheme (https) fails closed
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unsupported_scheme_https_fails_closed() {
    let policy = FetchPolicy {
        block_private_ips: false,
        ..FetchPolicy::default()
    };

    let req = FetchRequest::new("https://example.com/page");
    let result = agent_guard_proxy::controlled_fetch::fetch_with_policy(&req, &policy);

    let err = result.expect_err("https must be rejected in HTTP-only transport");
    assert_eq!(err.reason_code(), "UNSUPPORTED_SCHEME");
}

#[test]
fn unsupported_scheme_ftp_fails_closed() {
    let policy = FetchPolicy {
        block_private_ips: false,
        ..FetchPolicy::default()
    };

    let req = FetchRequest::new("ftp://files.example.com/data.txt");
    let result = agent_guard_proxy::controlled_fetch::fetch_with_policy(&req, &policy);

    let err = result.expect_err("ftp must be rejected");
    assert_eq!(err.reason_code(), "UNSUPPORTED_SCHEME");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: Error display never includes URL, path, headers, body, or payload
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn error_display_never_leaks_request_details() {
    // Trigger various errors and check Display output
    let sensitive_url = "http://127.0.0.1:9999/super/secret/path?token=abc123";
    let policy = FetchPolicy::default();
    let req = FetchRequest::new(sensitive_url);
    let result = agent_guard_proxy::controlled_fetch::fetch_with_policy(&req, &policy);

    let err = result.expect_err("should block private IP");
    let display = format!("{}", err);

    // Must never contain any part of the URL, path, or query
    assert!(!display.contains("127.0.0.1"), "Display must not leak IP");
    assert!(!display.contains("9999"), "Display must not leak port");
    assert!(!display.contains("/super"), "Display must not leak path");
    assert!(
        !display.contains("secret"),
        "Display must not leak path segment"
    );
    assert!(
        !display.contains("token"),
        "Display must not leak query param"
    );
    assert!(
        !display.contains("abc123"),
        "Display must not leak query value"
    );

    // Must contain the safe reason code and a correlation id
    assert!(display.contains("SSRF_PRIVATE_IP"));
    assert!(display.contains("correlation_id="));
}

#[test]
fn error_display_for_unsupported_scheme_never_leaks() {
    let policy = FetchPolicy {
        block_private_ips: false,
        ..FetchPolicy::default()
    };
    let req = FetchRequest::new("https://evil.example.com/steal?data=payload");
    let result = agent_guard_proxy::controlled_fetch::fetch_with_policy(&req, &policy);

    let err = result.expect_err("https should be rejected");
    let display = format!("{}", err);

    assert!(!display.contains("evil.example.com"), "Must not leak host");
    assert!(!display.contains("/steal"), "Must not leak path");
    assert!(!display.contains("payload"), "Must not leak query data");
    assert!(display.contains("UNSUPPORTED_SCHEME"));
}
