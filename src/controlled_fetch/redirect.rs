use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use url::Url;

use super::error::{BlockReason, FetchError};
use super::ip_validator::{validate_connected_ip, validate_url_target};
use super::policy::FetchPolicy;
use super::request::FetchRequest;

/// HTTP response from the transport layer.
#[derive(Debug, Clone)]
pub struct FetchResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    #[allow(dead_code)]
    pub final_url: String,
}

/// Trait abstracting the HTTP transport layer for testing.
///
/// In production, the default `SocketValidatingTransport` performs
/// a real HTTP/1.1 request with DNS rebinding protection.
/// In tests, a mock can return canned responses.
pub trait HttpTransport {
    fn execute(
        &self,
        request: &FetchRequest,
        policy: &FetchPolicy,
        correlation_id: &str,
    ) -> Result<FetchResponse, FetchError>;
}

/// Default transport: real HTTP/1.1 over validated TcpStream.
pub struct SocketValidatingTransport;

/// I/O timeout for connect, read, and write operations.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum size for the response header block (64 KiB).
const MAX_HEADER_BYTES: usize = 64 * 1024;

impl HttpTransport for SocketValidatingTransport {
    fn execute(
        &self,
        request: &FetchRequest,
        policy: &FetchPolicy,
        correlation_id: &str,
    ) -> Result<FetchResponse, FetchError> {
        real_http_request(request, policy, correlation_id)
    }
}

/// Perform a real bounded HTTP/1.1 GET over TcpStream.
///
/// 1. Parse URL → extract host, port, path.
/// 2. Resolve DNS, validate every address with `validate_connected_ip`.
/// 3. Connect with timeout to the first passing address.
/// 4. Write a minimal GET with safe headers (CRLF-injection rejected).
/// 5. Read bounded response headers, then bounded body.
fn real_http_request(
    request: &FetchRequest,
    policy: &FetchPolicy,
    correlation_id: &str,
) -> Result<FetchResponse, FetchError> {
    let parsed = Url::parse(request.url())
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?;

    // Scheme already validated upstream, but defense-in-depth.
    if parsed.scheme() != "http" {
        return Err(FetchError::new(
            BlockReason::UnsupportedScheme,
            correlation_id,
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| FetchError::new(BlockReason::TransportError, correlation_id))?
        .to_string();

    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    let request_uri = match parsed.query() {
        Some(q) => format!("{}?{}", path, q),
        None => path.to_string(),
    };

    // --- DNS resolution + IP validation ---
    let addr_str = format!("{}:{}", host, port);
    let addrs: Vec<_> = addr_str
        .to_socket_addrs()
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?
        .collect();

    if addrs.is_empty() {
        return Err(FetchError::new(BlockReason::TransportError, correlation_id));
    }

    // Validate ALL resolved addresses BEFORE connecting to any.
    if policy.block_private_ips {
        for addr in &addrs {
            validate_connected_ip(&addr.ip(), correlation_id)?;
        }
    }

    // --- Connect with timeout ---
    let mut stream: Option<TcpStream> = None;
    for addr in &addrs {
        if let Ok(s) = TcpStream::connect_timeout(addr, IO_TIMEOUT) {
            stream = Some(s);
            break;
        }
    }
    let mut stream =
        stream.ok_or_else(|| FetchError::new(BlockReason::TransportError, correlation_id))?;

    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?;

    // --- Build request ---
    // Validate host header value (no CRLF injection)
    let host_header_value = if port == 80 {
        host.clone()
    } else {
        format!("{}:{}", host, port)
    };
    reject_crlf(&host_header_value, correlation_id)?;

    let mut request_bytes = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        request_uri, host_header_value
    );

    // Append user-supplied headers (CRLF-injection check on each)
    for (name, value) in request.headers() {
        reject_crlf(name, correlation_id)?;
        reject_crlf(value, correlation_id)?;
        request_bytes.push_str(&format!("{}: {}\r\n", name, value));
    }
    request_bytes.push_str("\r\n");

    // --- Write request ---
    stream
        .write_all(request_bytes.as_bytes())
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?;
    stream
        .flush()
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?;

    // --- Read response headers (bounded) ---
    let mut reader = BufReader::new(&stream);
    let mut header_section = Vec::new();
    let mut total_header_bytes: usize = 0;

    // Read status line
    let mut status_line = String::new();
    let n = reader
        .read_line(&mut status_line)
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?;
    total_header_bytes += n;
    if total_header_bytes > MAX_HEADER_BYTES {
        return Err(FetchError::new(BlockReason::TransportError, correlation_id));
    }

    // Parse status code from "HTTP/1.x NNN ..."
    let status_code = parse_status_code(&status_line)
        .ok_or_else(|| FetchError::new(BlockReason::TransportError, correlation_id))?;

    // Read headers until empty line
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?;
        if n == 0 {
            break; // EOF
        }
        total_header_bytes += n;
        if total_header_bytes > MAX_HEADER_BYTES {
            return Err(FetchError::new(BlockReason::TransportError, correlation_id));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // End of headers
        }
        header_section.push(trimmed.to_string());
    }

    // Parse headers into (name, value) pairs
    let mut headers: Vec<(String, String)> = Vec::new();
    for raw in &header_section {
        if let Some((name, value)) = raw.split_once(':') {
            headers.push((name.trim().to_lowercase(), value.trim().to_string()));
        }
    }

    // --- Body size enforcement via Content-Length BEFORE reading ---
    if let Some(cl_str) = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .map(|(_, v)| v.clone())
    {
        if let Ok(cl) = cl_str.parse::<usize>() {
            if cl > policy.max_body_size {
                return Err(FetchError::new(
                    BlockReason::BodySizeLimitExceeded,
                    correlation_id,
                ));
            }
        }
    }

    // --- Read body (bounded to max_body_size + 1 to detect overflow) ---
    let read_limit = policy.max_body_size + 1;
    let mut body = Vec::new();
    reader
        .take(read_limit as u64)
        .read_to_end(&mut body)
        .map_err(|_| FetchError::new(BlockReason::TransportError, correlation_id))?;

    if body.len() > policy.max_body_size {
        return Err(FetchError::new(
            BlockReason::BodySizeLimitExceeded,
            correlation_id,
        ));
    }

    Ok(FetchResponse {
        status_code,
        headers,
        body,
        final_url: request.url().to_string(),
    })
}

/// Reject any string containing CR or LF (CRLF injection guard).
fn reject_crlf(value: &str, correlation_id: &str) -> Result<(), FetchError> {
    if value.contains('\r') || value.contains('\n') {
        return Err(FetchError::new(BlockReason::TransportError, correlation_id));
    }
    Ok(())
}

/// Parse the HTTP status code from the status line.
fn parse_status_code(line: &str) -> Option<u16> {
    // "HTTP/1.1 200 OK" → split by space, take second token
    let mut parts = line.split_whitespace();
    let _version = parts.next()?;
    let code_str = parts.next()?;
    code_str.parse::<u16>().ok()
}

/// Follow redirects with per-hop IP/host policy validation.
///
/// On each redirect hop:
/// 1. Validates the redirect target against the full IP/host policy.
/// 2. Enforces the maximum redirect count.
pub fn follow_redirects(
    req: &FetchRequest,
    policy: &FetchPolicy,
    correlation_id: &str,
) -> Result<FetchResponse, FetchError> {
    follow_redirects_with_transport(req, policy, correlation_id, &SocketValidatingTransport)
}

/// Internal implementation that accepts any `HttpTransport` for testability.
pub(crate) fn follow_redirects_with_transport(
    req: &FetchRequest,
    policy: &FetchPolicy,
    correlation_id: &str,
    transport: &dyn HttpTransport,
) -> Result<FetchResponse, FetchError> {
    let mut current_url = req.url().to_string();
    let mut hops: u32 = 0;

    loop {
        // Validate current URL against IP policy.
        if hops == 0 {
            validate_url_target(&current_url, policy, correlation_id)?;
        } else {
            validate_redirect_target(&current_url, policy, correlation_id)?;
        }

        // Build a FetchRequest for this hop (preserve original headers)
        let hop_req = {
            let mut r = FetchRequest::new(&current_url);
            for (name, value) in req.headers() {
                r = r.with_header(name, value);
            }
            r
        };

        // Execute the HTTP request
        let response = transport.execute(&hop_req, policy, correlation_id)?;

        // Check if it's a redirect
        if is_redirect(response.status_code) {
            hops += 1;
            if hops > policy.max_redirects {
                return Err(FetchError::new(
                    BlockReason::ExcessiveRedirects,
                    correlation_id,
                ));
            }

            // Extract the Location header
            let location = response
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone());

            if let Some(loc) = location {
                // Resolve relative redirects
                let base = Url::parse(&current_url).map_err(|_| {
                    FetchError::new(BlockReason::RedirectToPrivateIp, correlation_id)
                })?;
                let resolved = base.join(&loc).map_err(|_| {
                    FetchError::new(BlockReason::RedirectToPrivateIp, correlation_id)
                })?;

                // Reject redirect to non-http scheme
                if resolved.scheme() != "http" {
                    return Err(FetchError::new(
                        BlockReason::UnsupportedScheme,
                        correlation_id,
                    ));
                }

                current_url = resolved.to_string();

                // Validate the redirect target against IP/host policy
                validate_redirect_target(&current_url, policy, correlation_id)?;
            } else {
                // Redirect without Location — treat as final response
                return Ok(response);
            }
        } else {
            return Ok(response);
        }
    }
}

/// Validate a redirect target against IP policy, mapping any SSRF block
/// to the `RedirectToPrivateIp` reason.
fn validate_redirect_target(
    url: &str,
    policy: &FetchPolicy,
    correlation_id: &str,
) -> Result<(), FetchError> {
    validate_url_target(url, policy, correlation_id).map_err(|e| match e.reason() {
        BlockReason::SsrfPrivateIp => {
            FetchError::new(BlockReason::RedirectToPrivateIp, correlation_id)
        }
        _ => e,
    })
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Mock transport that returns pre-configured responses per URL.
    struct MockTransport {
        responses: RefCell<Vec<(&'static str, FetchResponse)>>,
    }

    impl MockTransport {
        fn new(responses: Vec<(&'static str, FetchResponse)>) -> Self {
            Self {
                responses: RefCell::new(responses),
            }
        }
    }

    impl HttpTransport for MockTransport {
        fn execute(
            &self,
            request: &FetchRequest,
            _policy: &FetchPolicy,
            _correlation_id: &str,
        ) -> Result<FetchResponse, FetchError> {
            let url = request.url();
            let responses = self.responses.borrow();
            for (prefix, response) in responses.iter() {
                if url.starts_with(prefix) {
                    return Ok(response.clone());
                }
            }
            Ok(FetchResponse {
                status_code: 200,
                headers: vec![("content-type".to_string(), "text/html".to_string())],
                body: Vec::new(),
                final_url: url.to_string(),
            })
        }
    }

    fn redirect_response(location: &str) -> FetchResponse {
        FetchResponse {
            status_code: 302,
            headers: vec![("Location".to_string(), location.to_string())],
            body: Vec::new(),
            final_url: String::new(),
        }
    }

    fn ok_response(url: &str) -> FetchResponse {
        FetchResponse {
            status_code: 200,
            headers: vec![("content-type".to_string(), "text/html".to_string())],
            body: b"OK".to_vec(),
            final_url: url.to_string(),
        }
    }

    #[test]
    fn test_redirect_to_private_blocked() {
        let policy = FetchPolicy::default();
        let req = FetchRequest::new("http://10.0.0.1/redirect");
        let result = follow_redirects(&req, &policy, "test-id");
        assert!(result.is_err());
    }

    #[test]
    fn test_redirect_hop_to_private_ip_is_blocked() {
        let transport = MockTransport::new(vec![
            (
                "http://203.0.113.1/start",
                redirect_response("http://192.168.1.1/secret"),
            ),
            (
                "http://192.168.1.1/secret",
                ok_response("http://192.168.1.1/secret"),
            ),
        ]);

        let policy = FetchPolicy::default();
        let req = FetchRequest::new("http://203.0.113.1/start");
        let result = follow_redirects_with_transport(&req, &policy, "redir-private", &transport);

        assert!(result.is_err(), "Redirect to private IP must be blocked");
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "REDIRECT_TO_PRIVATE_IP");
        assert_eq!(err.correlation_id(), "redir-private");
    }

    #[test]
    fn test_redirect_hop_to_loopback_is_blocked() {
        let transport = MockTransport::new(vec![(
            "http://203.0.113.1/",
            redirect_response("http://127.0.0.1/admin"),
        )]);

        let policy = FetchPolicy::default();
        let req = FetchRequest::new("http://203.0.113.1/");
        let result = follow_redirects_with_transport(&req, &policy, "redir-loopback", &transport);

        assert!(result.is_err(), "Redirect to loopback must be blocked");
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "REDIRECT_TO_PRIVATE_IP");
    }

    #[test]
    fn test_redirect_hop_to_metadata_is_blocked() {
        let transport = MockTransport::new(vec![(
            "http://203.0.113.1/",
            redirect_response("http://169.254.169.254/latest/meta-data/"),
        )]);

        let policy = FetchPolicy::default();
        let req = FetchRequest::new("http://203.0.113.1/");
        let result = follow_redirects_with_transport(&req, &policy, "redir-metadata", &transport);

        assert!(result.is_err(), "Redirect to metadata must be blocked");
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "REDIRECT_TO_PRIVATE_IP");
    }

    #[test]
    fn test_redirect_chain_multi_hop_to_private_is_blocked() {
        let transport = MockTransport::new(vec![
            (
                "http://203.0.113.1/hop1",
                redirect_response("http://198.51.100.1/hop2"),
            ),
            (
                "http://198.51.100.1/hop2",
                redirect_response("http://10.0.0.1/internal"),
            ),
            (
                "http://10.0.0.1/internal",
                ok_response("http://10.0.0.1/internal"),
            ),
        ]);

        let policy = FetchPolicy::default();
        let req = FetchRequest::new("http://203.0.113.1/hop1");
        let result = follow_redirects_with_transport(&req, &policy, "redir-chain-priv", &transport);

        assert!(
            result.is_err(),
            "Multi-hop redirect ending at private IP must be blocked"
        );
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "REDIRECT_TO_PRIVATE_IP");
    }

    #[test]
    fn test_excessive_redirects_blocked() {
        let transport = MockTransport::new(vec![
            (
                "http://203.0.113.1/r1",
                redirect_response("http://203.0.113.2/r2"),
            ),
            (
                "http://203.0.113.2/r2",
                redirect_response("http://203.0.113.3/r3"),
            ),
            (
                "http://203.0.113.3/r3",
                redirect_response("http://203.0.113.4/r4"),
            ),
            (
                "http://203.0.113.4/r4",
                redirect_response("http://203.0.113.5/r5"),
            ),
            (
                "http://203.0.113.5/r5",
                redirect_response("http://203.0.113.6/r6"),
            ),
            (
                "http://203.0.113.6/r6",
                redirect_response("http://203.0.113.7/r7"),
            ),
        ]);

        let policy = FetchPolicy {
            max_redirects: 3,
            ..FetchPolicy::default()
        };

        let req = FetchRequest::new("http://203.0.113.1/r1");
        let result = follow_redirects_with_transport(&req, &policy, "excessive-redir", &transport);

        assert!(result.is_err(), "Excessive redirects must be blocked");
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "EXCESSIVE_REDIRECTS");
        assert_eq!(err.correlation_id(), "excessive-redir");
    }

    #[test]
    fn test_redirect_within_limit_succeeds() {
        let transport = MockTransport::new(vec![
            (
                "http://203.0.113.1/start",
                redirect_response("http://203.0.113.2/middle"),
            ),
            (
                "http://203.0.113.2/middle",
                redirect_response("http://203.0.113.3/final"),
            ),
            (
                "http://203.0.113.3/final",
                ok_response("http://203.0.113.3/final"),
            ),
        ]);

        let policy = FetchPolicy::default();
        let req = FetchRequest::new("http://203.0.113.1/start");
        let result = follow_redirects_with_transport(&req, &policy, "valid-redir", &transport);

        assert!(
            result.is_ok(),
            "Redirect chain within limit to public IPs should succeed"
        );
        let resp = result.unwrap();
        assert_eq!(resp.status_code, 200);
    }

    #[test]
    fn test_redirect_at_exact_limit_succeeds() {
        let transport = MockTransport::new(vec![
            (
                "http://203.0.113.1/r1",
                redirect_response("http://203.0.113.2/r2"),
            ),
            (
                "http://203.0.113.2/r2",
                redirect_response("http://203.0.113.3/r3"),
            ),
            (
                "http://203.0.113.3/r3",
                redirect_response("http://203.0.113.4/final"),
            ),
            (
                "http://203.0.113.4/final",
                ok_response("http://203.0.113.4/final"),
            ),
        ]);

        let policy = FetchPolicy {
            max_redirects: 3,
            ..FetchPolicy::default()
        };

        let req = FetchRequest::new("http://203.0.113.1/r1");
        let result = follow_redirects_with_transport(&req, &policy, "exact-limit", &transport);

        assert!(
            result.is_ok(),
            "Redirect chain at exactly the limit should succeed"
        );
    }

    #[test]
    fn test_redirect_one_over_limit_blocked() {
        let transport = MockTransport::new(vec![
            (
                "http://203.0.113.1/r1",
                redirect_response("http://203.0.113.2/r2"),
            ),
            (
                "http://203.0.113.2/r2",
                redirect_response("http://203.0.113.3/r3"),
            ),
            (
                "http://203.0.113.3/r3",
                redirect_response("http://203.0.113.4/r4"),
            ),
            (
                "http://203.0.113.4/r4",
                redirect_response("http://203.0.113.5/final"),
            ),
            (
                "http://203.0.113.5/final",
                ok_response("http://203.0.113.5/final"),
            ),
        ]);

        let policy = FetchPolicy {
            max_redirects: 3,
            ..FetchPolicy::default()
        };

        let req = FetchRequest::new("http://203.0.113.1/r1");
        let result = follow_redirects_with_transport(&req, &policy, "over-limit", &transport);

        assert!(result.is_err(), "One over the limit must be blocked");
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "EXCESSIVE_REDIRECTS");
    }

    #[test]
    fn test_redirect_to_ipv6_loopback_blocked() {
        let transport = MockTransport::new(vec![(
            "http://203.0.113.1/",
            redirect_response("http://[::1]/admin"),
        )]);

        let policy = FetchPolicy::default();
        let req = FetchRequest::new("http://203.0.113.1/");
        let result = follow_redirects_with_transport(&req, &policy, "redir-v6", &transport);

        assert!(result.is_err(), "Redirect to IPv6 loopback must be blocked");
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "REDIRECT_TO_PRIVATE_IP");
    }

    #[test]
    fn test_redirect_to_link_local_blocked() {
        let transport = MockTransport::new(vec![(
            "http://203.0.113.1/",
            redirect_response("http://169.254.1.1/"),
        )]);

        let policy = FetchPolicy::default();
        let req = FetchRequest::new("http://203.0.113.1/");
        let result = follow_redirects_with_transport(&req, &policy, "redir-linklocal", &transport);

        assert!(
            result.is_err(),
            "Redirect to link-local address must be blocked"
        );
        let err = result.unwrap_err();
        assert_eq!(err.reason_code(), "REDIRECT_TO_PRIVATE_IP");
    }
}
