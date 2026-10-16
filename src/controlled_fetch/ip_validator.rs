use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use url::Url;

use super::error::{BlockReason, FetchError};
use super::policy::FetchPolicy;

/// IPv4 ranges that must never be reachable through the gateway.
///
/// Table-driven on purpose: the previous hand-rolled `if` chain silently omitted
/// whole ranges, and two of those omissions were reachable on a normal Linux host
/// (`0.0.0.0` connects to loopback; `100.64.0.0/10` is where Tailscale parks its
/// addresses). One predicate serves every caller, so a missing entry is a hole in
/// all of them.
///
/// `(network, prefix_len)`, network in host byte order.
const BLOCKED_IPV4_CIDRS: &[(u32, u8)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8        "this network"; 0.0.0.0 reaches loopback
    (0x0A00_0000, 8),  // 10.0.0.0/8       RFC 1918
    (0x6440_0000, 10), // 100.64.0.0/10    RFC 6598 CGNAT (Tailscale et al.)
    (0x7F00_0000, 8),  // 127.0.0.0/8      loopback
    (0xA9FE_0000, 16), // 169.254.0.0/16   link-local, incl. cloud metadata
    (0xAC10_0000, 12), // 172.16.0.0/12    RFC 1918
    (0xC000_0000, 24), // 192.0.0.0/24     IETF protocol assignments
    (0xC0A8_0000, 16), // 192.168.0.0/16   RFC 1918
    (0xC612_0000, 15), // 198.18.0.0/15    benchmarking
    (0xF000_0000, 4),  // 240.0.0.0/4      reserved, incl. 255.255.255.255
];

/// Check if an IPv4 address is reserved, private, loopback, or metadata.
///
/// Deliberately conservative: only globally routable space is allowed, so
/// special-purpose ranges fail closed rather than requiring an entry each time
/// IANA adds one. The TEST-NET ranges (`192.0.2.0/24`, `198.51.100.0/24`,
/// `203.0.113.0/24`) stay allowed: they are unroutable documentation space and
/// are used by the test suite.
pub fn is_blocked_ipv4(ip: &Ipv4Addr) -> bool {
    let value = u32::from(*ip);
    BLOCKED_IPV4_CIDRS.iter().any(|&(network, prefix)| {
        let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
        value & mask == network & mask
    })
}

/// Check if an IPv6 address is blocked.
///
/// Covers loopback, the unspecified address (`::`, which routes to `::1` on
/// Linux and was previously allowed), multicast, IPv4-mapped addresses,
/// link-local, and unique-local space.
pub fn is_blocked_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return true;
    }
    // IPv4-mapped addresses: check the embedded IPv4.
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(&ipv4);
    }
    let segments = ip.segments();
    // Link-local: fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // Unique local: fc00::/7
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    false
}

/// Check if an IP address is blocked by policy.
pub fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

/// Normalize a `host[:port]` string so `to_socket_addrs` can resolve it.
///
/// A bracketed IPv6 literal without a port needs one appended; a bare hostname
/// without a port defaults to 80.
pub(crate) fn with_default_port(host_port: &str) -> String {
    if let Some(rest) = host_port.strip_prefix('[') {
        // Bracketed IPv6 literal: append the default port only if none follows the bracket.
        if rest.contains("]:") {
            host_port.to_string()
        } else {
            format!("{}:80", host_port)
        }
    } else if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:80", host_port)
    }
}

/// Resolve a `host[:port]` endpoint and return ONLY the addresses that passed
/// the IP policy.
///
/// Callers MUST connect to the returned addresses rather than to the original
/// host string. Re-resolving after validation is a TOCTOU hole: a hostile name
/// can answer with a public address for the check and a loopback address for the
/// connection. Returning the validated addresses removes the second lookup
/// entirely instead of guarding it.
///
/// Fails closed: an unresolvable name, an empty result, or any blocked address
/// is an error.
pub fn resolve_and_check(
    host_port: &str,
    correlation_id: &str,
) -> Result<Vec<SocketAddr>, FetchError> {
    let target = with_default_port(host_port);
    let addrs: Vec<SocketAddr> = target
        .to_socket_addrs()
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?
        .collect();

    if addrs.is_empty() {
        return Err(FetchError::new(BlockReason::TransportError, correlation_id));
    }

    for addr in &addrs {
        if is_blocked_ip(&addr.ip()) {
            return Err(FetchError::new(BlockReason::SsrfPrivateIp, correlation_id));
        }
    }

    Ok(addrs)
}

/// Validate a `host:port` endpoint by resolving it and checking each
/// address against the blocked-IP policy. Used by the forward-proxy server
/// before opening a tunnel (CONNECT) or proxying an absolute request.
///
/// Prefer [`resolve_and_check`] when the caller then connects: it hands back the
/// validated addresses so the connection cannot diverge from the check.
pub fn validate_endpoint(host_port: &str, correlation_id: &str) -> Result<(), FetchError> {
    resolve_and_check(host_port, correlation_id).map(|_| ())
}

/// Validate a URL target against the IP policy.
///
/// Resolves the hostname and checks all resulting IPs, blocking if any resolved
/// address is private, loopback, link-local, unspecified, or metadata. Fails
/// closed when the name cannot be resolved.
pub fn validate_url_target(
    url_str: &str,
    policy: &FetchPolicy,
    correlation_id: &str,
) -> Result<(), FetchError> {
    if !policy.block_private_ips {
        return Ok(());
    }

    let url = Url::parse(url_str)
        .map_err(|_| FetchError::new(BlockReason::SsrfPrivateIp, correlation_id))?;

    let host = url
        .host_str()
        .ok_or_else(|| FetchError::new(BlockReason::SsrfPrivateIp, correlation_id))?;

    // Try parsing as IP address directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(&ip) {
            return Err(FetchError::new(BlockReason::SsrfPrivateIp, correlation_id));
        }
        return Ok(());
    }

    // Resolve hostname via DNS. Resolution failure is a deny, not a pass:
    // an unverifiable destination must never be treated as safe.
    let port = url.port_or_known_default().unwrap_or(80);
    let addr_str = format!("{}:{}", host, port);

    let addrs: Vec<SocketAddr> = addr_str
        .to_socket_addrs()
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?
        .collect();

    if addrs.is_empty() {
        return Err(FetchError::new(BlockReason::TransportError, correlation_id));
    }

    for addr in &addrs {
        if is_blocked_ip(&addr.ip()) {
            return Err(FetchError::new(BlockReason::SsrfPrivateIp, correlation_id));
        }
    }

    Ok(())
}

/// Re-validate an address about to be connected to (for DNS rebinding protection).
///
/// Callers that resolve once and connect to the validated address do not need
/// this, but it stays available for any path that receives an address from
/// elsewhere.
pub fn validate_connected_ip(ip: &IpAddr, correlation_id: &str) -> Result<(), FetchError> {
    if is_blocked_ip(ip) {
        return Err(FetchError::new(BlockReason::DnsRebinding, correlation_id));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Address policy table: every entry is a destination that must be blocked,
    /// with the reason it exists. Additions land here first.
    const MUST_BLOCK_V4: &[(&str, &str)] = &[
        ("0.0.0.0", "unspecified; a connect reaches loopback"),
        ("0.1.2.3", "0.0.0.0/8 as a whole, not just the zero address"),
        ("10.0.0.1", "RFC 1918"),
        ("10.255.255.255", "RFC 1918 upper bound"),
        (
            "100.64.0.1",
            "RFC 6598 CGNAT lower bound; Tailscale hands these out",
        ),
        ("100.127.255.255", "RFC 6598 upper bound"),
        ("127.0.0.1", "loopback"),
        ("127.1.2.3", "loopback /8"),
        ("169.254.0.1", "link-local lower bound"),
        ("169.254.169.254", "cloud metadata"),
        ("172.16.0.1", "RFC 1918 lower bound"),
        ("172.31.255.255", "RFC 1918 upper bound"),
        ("192.0.0.1", "IETF protocol assignments"),
        ("192.168.0.1", "RFC 1918"),
        ("198.18.0.1", "benchmarking lower bound"),
        ("198.19.255.255", "benchmarking upper bound"),
        ("240.0.0.1", "reserved"),
        ("255.255.255.255", "broadcast"),
    ];

    const MUST_ALLOW_V4: &[(&str, &str)] = &[
        ("8.8.8.8", "public resolver"),
        ("1.1.1.1", "public resolver"),
        ("172.15.255.255", "just below RFC 1918 172.16/12"),
        ("172.32.0.0", "just above RFC 1918 172.16/12"),
        ("100.63.255.255", "just below CGNAT"),
        ("100.128.0.0", "just above CGNAT"),
        ("198.17.255.255", "just below benchmarking"),
        ("198.20.0.0", "just above benchmarking"),
        ("192.0.1.1", "just above 192.0.0.0/24"),
        ("203.0.113.1", "TEST-NET-3, unroutable documentation space"),
    ];

    const MUST_BLOCK_V6: &[(&str, &str)] = &[
        ("::1", "loopback"),
        ("::", "unspecified; a connect reaches ::1 on Linux"),
        ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
        ("::ffff:10.0.0.1", "IPv4-mapped RFC 1918"),
        ("fe80::1", "link-local"),
        ("fc00::1", "unique local"),
        ("fd7a:115c:a1e0::1", "unique local (Tailscale-style ULA)"),
        ("ff02::1", "multicast"),
    ];

    fn parse_v4(s: &str) -> Ipv4Addr {
        s.parse().expect("valid IPv4 literal in test table")
    }

    fn parse_v6(s: &str) -> Ipv6Addr {
        s.parse().expect("valid IPv6 literal in test table")
    }

    #[test]
    fn address_policy_blocks_every_listed_v4_range() {
        for (addr, why) in MUST_BLOCK_V4 {
            assert!(
                is_blocked_ipv4(&parse_v4(addr)),
                "{addr} must be blocked: {why}"
            );
        }
    }

    #[test]
    fn address_policy_allows_global_v4_and_the_boundary_case_below_each_range() {
        for (addr, why) in MUST_ALLOW_V4 {
            assert!(
                !is_blocked_ipv4(&parse_v4(addr)),
                "{addr} must be allowed: {why}"
            );
        }
    }

    #[test]
    fn address_policy_blocks_every_listed_v6_range() {
        for (addr, why) in MUST_BLOCK_V6 {
            assert!(
                is_blocked_ipv6(&parse_v6(addr)),
                "{addr} must be blocked: {why}"
            );
        }
    }

    #[test]
    fn address_policy_allows_global_v6() {
        assert!(!is_blocked_ipv6(&parse_v6("2606:4700:4700::1111")));
    }

    #[test]
    fn test_loopback_blocked() {
        assert!(is_blocked_ipv4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_blocked_ipv4(&Ipv4Addr::new(127, 0, 0, 2)));
    }

    #[test]
    fn test_private_10_blocked() {
        assert!(is_blocked_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_blocked_ipv4(&Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn test_private_172_blocked() {
        assert!(is_blocked_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_blocked_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        // 172.15 and 172.32 should NOT be blocked
        assert!(!is_blocked_ipv4(&Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_blocked_ipv4(&Ipv4Addr::new(172, 32, 0, 1)));
    }

    #[test]
    fn test_private_192_168_blocked() {
        assert!(is_blocked_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_blocked_ipv4(&Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn test_link_local_blocked() {
        assert!(is_blocked_ipv4(&Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_blocked_ipv4(&Ipv4Addr::new(169, 254, 169, 254)));
    }

    #[test]
    fn test_public_allowed() {
        assert!(!is_blocked_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_blocked_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_blocked_ipv4(&Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn test_ipv6_loopback_blocked() {
        assert!(is_blocked_ipv6(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_validate_url_loopback() {
        let policy = FetchPolicy::default();
        let result = validate_url_target("http://127.0.0.1/path", &policy, "test-id");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_url_metadata() {
        let policy = FetchPolicy::default();
        let result = validate_url_target(
            "http://169.254.169.254/latest/meta-data/",
            &policy,
            "test-id",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_url_unspecified_address_is_blocked() {
        let policy = FetchPolicy::default();
        for url in ["http://0.0.0.0/", "http://[::]/", "http://100.64.0.1/"] {
            let result = validate_url_target(url, &policy, "test-id");
            assert!(result.is_err(), "{url} must be blocked");
        }
    }

    #[test]
    fn test_validate_connected_ip_blocks_private() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let result = validate_connected_ip(&loopback, "test-rebind");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "DNS_REBINDING");
        assert_eq!(err.correlation_id(), "test-rebind");
    }

    #[test]
    fn test_validate_connected_ip_allows_public() {
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let result = validate_connected_ip(&public, "test-ok");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_connected_ip_blocks_metadata() {
        let metadata: IpAddr = "169.254.169.254".parse().unwrap();
        let result = validate_connected_ip(&metadata, "test-metadata-rebind");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "DNS_REBINDING");
    }

    #[test]
    fn test_validate_connected_ip_blocks_ipv6_loopback() {
        let loopback: IpAddr = "::1".parse().unwrap();
        let result = validate_connected_ip(&loopback, "test-v6-rebind");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "DNS_REBINDING");
    }

    // --- resolve_and_check: the seam the proxy connects through ---

    #[test]
    fn resolve_and_check_rejects_literal_blocked_endpoints() {
        // No sockets needed: these are IP literals, so resolution is local.
        let cases = [
            ("0.0.0.0:80", "unspecified; reaches loopback"),
            ("0.0.0.0", "unspecified without an explicit port"),
            ("[::]:80", "IPv6 unspecified"),
            ("100.64.0.1:80", "CGNAT"),
            ("127.0.0.1:80", "loopback"),
            ("[::1]:443", "IPv6 loopback"),
            ("169.254.169.254:80", "cloud metadata"),
        ];
        for (endpoint, why) in cases {
            let result = resolve_and_check(endpoint, "test-resolve");
            assert!(result.is_err(), "{endpoint} must be rejected: {why}");
        }
    }

    #[test]
    fn resolve_and_check_returns_the_addresses_it_validated() {
        let addrs = resolve_and_check("8.8.8.8:443", "test-resolve").expect("public literal");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].to_string(), "8.8.8.8:443");
        assert!(!is_blocked_ip(&addrs[0].ip()));
    }

    #[test]
    fn resolve_and_check_fails_closed_on_unresolvable_name() {
        // `.invalid` is reserved by RFC 2606 and never resolves.
        let result = resolve_and_check("nonexistent.invalid:80", "test-resolve");
        assert!(
            result.is_err(),
            "an unresolvable name must be denied, not allowed through"
        );
    }

    #[test]
    fn validate_endpoint_delegates_to_resolve_and_check() {
        assert!(validate_endpoint("127.0.0.1:80", "t").is_err());
        assert!(validate_endpoint("198.18.0.1:80", "t").is_err());
        assert!(validate_endpoint("8.8.8.8:80", "t").is_ok());
    }

    #[test]
    fn with_default_port_handles_bracketed_ipv6() {
        assert_eq!(with_default_port("example.com"), "example.com:80");
        assert_eq!(with_default_port("example.com:8080"), "example.com:8080");
        assert_eq!(with_default_port("[::1]"), "[::1]:80");
        assert_eq!(with_default_port("[::1]:443"), "[::1]:443");
    }
}
