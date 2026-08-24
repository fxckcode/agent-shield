use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use url::Url;

use super::error::{BlockReason, FetchError};
use super::policy::FetchPolicy;

/// Check if an IPv4 address is private, loopback, link-local, or metadata.
fn is_blocked_ipv4(ip: &Ipv4Addr) -> bool {
    // Loopback: 127.0.0.0/8
    if ip.is_loopback() {
        return true;
    }
    // Private: 10.0.0.0/8
    if ip.octets()[0] == 10 {
        return true;
    }
    // Private: 172.16.0.0/12
    if ip.octets()[0] == 172 && (ip.octets()[1] >= 16 && ip.octets()[1] <= 31) {
        return true;
    }
    // Private: 192.168.0.0/16
    if ip.octets()[0] == 192 && ip.octets()[1] == 168 {
        return true;
    }
    // Link-local: 169.254.0.0/16 (includes cloud metadata 169.254.169.254)
    if ip.octets()[0] == 169 && ip.octets()[1] == 254 {
        return true;
    }
    false
}

/// Check if an IPv6 address is blocked.
fn is_blocked_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback ::1
    if ip.is_loopback() {
        return true;
    }
    // IPv4-mapped addresses: check the embedded IPv4
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(&ipv4);
    }
    // Link-local: fe80::/10
    let segments = ip.segments();
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

/// Validate a URL target against the IP policy.
///
/// Resolves the hostname and checks all resulting IPs.
/// Blocks if any resolved IP is private/loopback/link-local/metadata.
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

    // Resolve hostname via DNS
    let port = url.port_or_known_default().unwrap_or(80);
    let addr_str = format!("{}:{}", host, port);

    if let Ok(addrs) = addr_str.to_socket_addrs() {
        for addr in addrs {
            if is_blocked_ip(&addr.ip()) {
                return Err(FetchError::new(BlockReason::SsrfPrivateIp, correlation_id));
            }
        }
    }

    Ok(())
}

/// Re-validate after connection (for DNS rebinding protection).
///
/// Called at socket-connect time to re-check the resolved IP.
pub fn validate_connected_ip(ip: &IpAddr, correlation_id: &str) -> Result<(), FetchError> {
    if is_blocked_ip(ip) {
        return Err(FetchError::new(BlockReason::DnsRebinding, correlation_id));
    }
    Ok(())
}

/// Validate a `host:port` endpoint by resolving it and checking each
/// address against the blocked-IP policy. Used by the forward-proxy server
/// before opening a tunnel (CONNECT) or proxying an absolute request.
///
/// Returns Ok if the endpoint is allowed, Err(SsrfPrivateIp) otherwise.
pub fn validate_endpoint(host_port: &str, correlation_id: &str) -> Result<(), FetchError> {
    let addr_str = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{}:80", host_port)
    };
    let addrs = addr_str
        .to_socket_addrs()
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?;
    for addr in addrs {
        if is_blocked_ip(&addr.ip()) {
            return Err(FetchError::new(BlockReason::SsrfPrivateIp, correlation_id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
