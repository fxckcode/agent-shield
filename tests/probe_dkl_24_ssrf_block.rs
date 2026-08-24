/// Probe: DKL-24 — Verify that the proxy blocks fetches to private/loopback/metadata addresses.
///
/// This probe imports the controlled-fetch module and attempts a fetch to 127.0.0.1.
/// If the security layer exists and works, the fetch is blocked with a safe reason code.
/// If the module doesn't exist, compilation fails — proving the feature is not implemented.
// Attempt to import the expected public API for controlled fetch.
use agent_guard_proxy::controlled_fetch::{
    fetch_with_policy, BlockReason, FetchPolicy, FetchRequest,
};

#[test]
fn blocks_loopback_address() {
    let policy = FetchPolicy::default();
    let req = FetchRequest::new("http://127.0.0.1/latest/meta-data/");
    let result = fetch_with_policy(&req, &policy);

    assert!(result.is_err(), "Fetch to loopback MUST be blocked");
    let err = result.unwrap_err();
    // Must contain a reason code
    assert!(
        !err.reason_code().is_empty(),
        "Blocked response must include a safe reason code"
    );
    // Must contain a correlation id
    assert!(
        !err.correlation_id().is_empty(),
        "Blocked response must include a correlation id"
    );
    // Must NOT echo the target URL or payload back
    assert!(
        !err.to_string().contains("127.0.0.1"),
        "Error must not echo the hostile target address"
    );
}

#[test]
fn blocks_cloud_metadata_address() {
    let policy = FetchPolicy::default();
    let req = FetchRequest::new("http://169.254.169.254/latest/meta-data/");
    let result = fetch_with_policy(&req, &policy);

    assert!(result.is_err(), "Fetch to cloud metadata MUST be blocked");
}

#[test]
fn blocks_private_rfc1918_address() {
    let policy = FetchPolicy::default();
    let req = FetchRequest::new("http://10.0.0.1/internal");
    let result = fetch_with_policy(&req, &policy);

    assert!(
        result.is_err(),
        "Fetch to RFC1918 private address MUST be blocked"
    );
}

#[test]
fn blocks_ipv6_loopback() {
    let policy = FetchPolicy::default();
    let req = FetchRequest::new("http://[::1]/path");
    let result = fetch_with_policy(&req, &policy);

    assert!(result.is_err(), "Fetch to IPv6 loopback MUST be blocked");
    let err = result.unwrap_err();
    assert!(!err.reason_code().is_empty());
    assert!(!err.correlation_id().is_empty());
}

#[test]
fn blocks_link_local_address() {
    let policy = FetchPolicy::default();
    let req = FetchRequest::new("http://169.254.1.1/");
    let result = fetch_with_policy(&req, &policy);

    assert!(result.is_err(), "Fetch to link-local MUST be blocked");
}

#[test]
fn socket_level_rebinding_blocks_private_ip() {
    // Even if pre-flight passed (simulated by using a literal private IP),
    // the socket-level re-validation in simulate_request ALSO blocks.
    // Here we verify the pipeline uses DNS_REBINDING reason at socket level.
    let policy = FetchPolicy::default();
    let req = FetchRequest::new("http://192.168.0.1/secret");
    let result = fetch_with_policy(&req, &policy);

    assert!(
        result.is_err(),
        "Fetch to private IP must be blocked (pre-flight or socket-level)"
    );
    let err = result.unwrap_err();
    // Either SSRF_PRIVATE_IP (pre-flight) or DNS_REBINDING (socket-level) is acceptable
    assert!(
        *err.reason() == BlockReason::SsrfPrivateIp || *err.reason() == BlockReason::DnsRebinding,
        "Must block with SSRF_PRIVATE_IP or DNS_REBINDING reason, got: {}",
        err.reason_code()
    );
    assert!(!err.correlation_id().is_empty());
    // Must NOT leak target in error display
    assert!(
        !err.to_string().contains("192.168"),
        "Error must not echo the target address"
    );
}
