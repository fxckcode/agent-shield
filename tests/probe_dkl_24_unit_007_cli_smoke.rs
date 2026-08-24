//! Integration smoke tests for the CLI adapter binary.
//!
//! Verifies that the `agent-guard-proxy` binary exposes the controlled-fetch
//! library through a minimal CLI surface with safe, structured output.

use std::process::Command;

/// Path to the compiled binary under test.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agent-shield")
}

#[test]
fn help_exits_zero_and_mentions_fetch() {
    let output = Command::new(bin())
        .arg("--help")
        .output()
        .expect("failed to execute binary");

    assert!(
        output.status.success(),
        "expected exit 0 for --help, got {:?}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.to_lowercase().contains("fetch"),
        "help output must mention 'fetch', got: {}",
        combined
    );
}

#[test]
fn fetch_unsupported_scheme_exits_nonzero_with_safe_json() {
    let output = Command::new(bin())
        .args(["fetch", "https://example.com"])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "expected nonzero exit for unsupported scheme"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Must contain the reason code
    assert!(
        stdout.contains("UNSUPPORTED_SCHEME"),
        "output must contain UNSUPPORTED_SCHEME, got: {}",
        stdout
    );

    // Must contain a correlation_id field
    assert!(
        stdout.contains("correlation_id"),
        "output must contain correlation_id, got: {}",
        stdout
    );

    // Must NOT leak URL, host, path, or query
    assert!(
        !stdout.contains("example.com"),
        "output must not contain hostname"
    );
    assert!(
        !stdout.contains("https://"),
        "output must not contain the URL scheme prefix"
    );
}

#[test]
fn fetch_private_ip_exits_nonzero_with_safe_json() {
    let url = "http://127.0.0.1:9/secret?token=redacted-test-value";
    let output = Command::new(bin())
        .args(["fetch", url])
        .output()
        .expect("failed to execute binary");

    assert!(
        !output.status.success(),
        "expected nonzero exit for private IP"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Must contain the reason code
    assert!(
        stdout.contains("SSRF_PRIVATE_IP"),
        "output must contain SSRF_PRIVATE_IP, got: {}",
        stdout
    );

    // Must contain a correlation_id field
    assert!(
        stdout.contains("correlation_id"),
        "output must contain correlation_id, got: {}",
        stdout
    );

    // Must NOT leak any part of the URL
    assert!(
        !stdout.contains("127.0.0.1"),
        "output must not contain IP address"
    );
    assert!(!stdout.contains("/secret"), "output must not contain path");
    assert!(
        !stdout.contains("token"),
        "output must not contain query parameter name"
    );
    assert!(
        !stdout.contains("redacted-test-value"),
        "output must not contain query parameter value"
    );
    assert!(
        !stdout.contains("http://"),
        "output must not contain scheme prefix"
    );
}

#[test]
fn missing_command_exits_nonzero_without_panic() {
    let output = Command::new(bin())
        .output()
        .expect("failed to execute binary");

    // Must exit nonzero
    assert!(
        !output.status.success(),
        "expected nonzero exit for missing command"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Must not panic
    assert!(
        !combined.contains("panicked"),
        "must not panic on missing command"
    );
    assert!(
        !combined.contains("thread 'main' panicked"),
        "must not show panic trace"
    );
}

#[test]
fn fetch_missing_url_exits_nonzero_without_panic() {
    let output = Command::new(bin())
        .args(["fetch"])
        .output()
        .expect("failed to execute binary");

    // Must exit nonzero
    assert!(
        !output.status.success(),
        "expected nonzero exit for missing URL argument"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // Must not panic
    assert!(
        !combined.contains("panicked"),
        "must not panic on missing URL"
    );
}
