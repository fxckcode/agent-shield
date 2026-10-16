//! Forward-proxy server with destination validation.
//!
//! Listens on `127.0.0.1:<port>` and handles absolute-form HTTP requests
//! (`GET http://host/path`) and CONNECT tunnels. Every destination is
//! resolved and validated against the blocked-IP policy BEFORE the
//! connection is opened, and the connection uses exactly the addresses that
//! passed that check.
//!
//! Why the addresses matter: resolving the hostname a second time at connect
//! time re-opens a TOCTOU window, where a hostile name answers with a public
//! address for the check and a loopback address for the connection. This module
//! therefore never calls `TcpStream::connect` on a host string.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Once;
use std::thread;
use std::time::Duration;

use crate::controlled_fetch::ip_validator::{resolve_and_check, with_default_port};
use crate::controlled_fetch::{BlockReason, FetchError};

/// Maximum request-line length we accept (bytes) before rejecting.
const MAX_LINE: usize = 16 * 1024;
/// Budget for establishing an upstream connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for a single read or write on either socket. Without these a client
/// that connects and then stays silent holds a thread forever.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Correlation id generator using a thread-safe counter + process hint.
fn correlation_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    format!("fwd-{:06x}-{:x}", n, std::process::id())
}

/// Escape a string so it can be embedded in a JSON string literal.
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn blocked_response(reason: &BlockReason, corr: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
         {{\"status\":\"blocked\",\"reason_code\":\"{}\",\"correlation_id\":\"{}\"}}",
        reason.code(),
        corr
    )
    .into_bytes()
}

fn bad_request(msg: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
         {{\"status\":\"error\",\"message\":\"{}\"}}",
        json_escape(msg)
    )
    .into_bytes()
}

fn bad_gateway(err: &std::io::Error) -> Vec<u8> {
    format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
         {{\"status\":\"error\",\"message\":\"upstream connect failed: {}\"}}",
        json_escape(&err.to_string())
    )
    .into_bytes()
}

/// Whether this binary honors the AGP_ALLOW_PRIVATE escape (same env var
/// as the fetch path; deliberately shared so tests can flip both).
///
/// Warns exactly once per process, as the README promises.
fn allow_private() -> bool {
    static WARN: Once = Once::new();
    let enabled = std::env::var("AGP_ALLOW_PRIVATE")
        .map(|v| v == "1")
        .unwrap_or(false);
    if enabled {
        WARN.call_once(|| {
            eprintln!(
                "agent-shield: WARNING — AGP_ALLOW_PRIVATE=1 disables the private-IP block. \
                 Testing only, never in production."
            );
        });
    }
    enabled
}

/// Read one request line (CRLF terminated) from the stream.
fn read_line(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while buf.len() < MAX_LINE {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
            }
            Err(e) => return Err(e),
        }
    }
    let s = String::from_utf8_lossy(&buf).trim_end().to_string();
    Ok(s)
}

/// Resolve an endpoint and return the addresses the caller is allowed to connect to.
///
/// Honors the `AGP_ALLOW_PRIVATE` testing escape, which resolves without applying
/// the policy.
fn checked_addrs(host_port: &str, corr: &str) -> Result<Vec<SocketAddr>, FetchError> {
    if allow_private() {
        let target = with_default_port(host_port);
        let addrs: Vec<SocketAddr> = target
            .to_socket_addrs()
            .map_err(|_| FetchError::new(BlockReason::TransportError, corr))?
            .collect();
        if addrs.is_empty() {
            return Err(FetchError::new(BlockReason::TransportError, corr));
        }
        return Ok(addrs);
    }
    resolve_and_check(host_port, corr)
}

/// Connect to one of the addresses that already passed validation, with timeouts.
///
/// Deliberately takes `SocketAddr`s, never a host: the address connected to must
/// be the address that was checked.
fn connect_validated(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last_error: Option<std::io::Error> = None;
    for addr in addrs {
        match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                return Ok(stream);
            }
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::other("no candidate address")))
}

/// Handle a CONNECT request: validate destination, reply 200, then tunnel.
fn handle_connect(host_port: &str, mut client: TcpStream, corr: &str) -> std::io::Result<()> {
    let addrs = match checked_addrs(host_port, corr) {
        Ok(addrs) => addrs,
        Err(e) => {
            let _ = client.write_all(&blocked_response(e.reason(), corr));
            let _ = client.flush();
            let _ = client.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
    };

    // Drain the client's headers up to CRLFCRLF. The request line was already
    // consumed, so the remaining headers would otherwise be forwarded into the
    // tunnel as if they were payload. Anything read past the terminator belongs
    // to the tunnel (a pipelined TLS ClientHello, for example) and is returned
    // here so it can be forwarded after the upstream is up.
    let pending = drain_headers(&mut client)?;

    let mut upstream = match connect_validated(&addrs) {
        Ok(s) => s,
        Err(err) => {
            let _ = client.write_all(&bad_gateway(&err));
            let _ = client.flush();
            let _ = client.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
    };

    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    let _ = client.flush();

    if !pending.is_empty() {
        let _ = upstream.write_all(&pending);
        let _ = upstream.flush();
    }

    // Bidirectional tunnel: client -> upstream and upstream -> client.
    let mut client_clone = client
        .try_clone()
        .map_err(|e| std::io::Error::new(e.kind(), e.to_string()))?;
    let mut upstream_clone = upstream
        .try_clone()
        .map_err(|e| std::io::Error::new(e.kind(), e.to_string()))?;

    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut client, &mut upstream);
    });
    let t2 = thread::spawn(move || {
        let _ = std::io::copy(&mut upstream_clone, &mut client_clone);
    });
    let _ = t1.join();
    let _ = t2.join();
    Ok(())
}

/// Rewrite the Host header inside a raw header block (up to CRLFCRLF) to the
/// absolute target host, and force `Connection: close`.
///
/// Forcing close is what lets the response relay below terminate on EOF instead
/// of blocking on a keep-alive upstream we do not parse.
fn rewrite_request_headers(headers: &[u8], host: &str, port: u16) -> Vec<u8> {
    let host_header = if port == 80 || port == 443 {
        format!("Host: {}", host)
    } else {
        format!("Host: {}:{}", host, port)
    };
    let text = String::from_utf8_lossy(headers);
    let mut out = Vec::with_capacity(headers.len() + 64);
    let mut host_found = false;
    for (i, line) in text.split_inclusive("\r\n").enumerate() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") {
            out.extend_from_slice(format!("{}\r\n", host_header).as_bytes());
            host_found = true;
        } else if lower.starts_with("connection:") {
            // Dropped: exactly one Connection header is appended below.
        } else if line == "\r\n" && !host_found {
            // End of headers with no Host → insert before the blank line.
            out.extend_from_slice(format!("{}\r\n", host_header).as_bytes());
            host_found = true;
            out.extend_from_slice(line.as_bytes());
        } else {
            out.extend_from_slice(line.as_bytes());
        }
        if i > 64 {
            break;
        }
    }
    if !host_found {
        out.extend_from_slice(format!("{}\r\n", host_header).as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n");
    out
}

/// Consume request headers from the client up to and including CRLFCRLF, and
/// return the bytes that were read past the terminator.
///
/// Those trailing bytes are tunnel payload, not headers, and dropping them
/// truncates a pipelined client handshake.
fn drain_headers(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = [0u8; 4096];
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let n = client.read(&mut buf)?;
        if n == 0 {
            return Ok(Vec::new());
        }
        acc.extend_from_slice(&buf[..n]);
        if let Some(pos) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(acc[pos + 4..].to_vec());
        }
        if acc.len() > MAX_LINE * 4 {
            return Ok(Vec::new());
        }
    }
}

/// Handle an absolute-form HTTP request (GET http://host/path): validate
/// the destination, then proxy the request line + headers + body.
fn handle_absolute(client: &mut TcpStream, request_line: &str, corr: &str) -> std::io::Result<()> {
    // request_line e.g. "GET http://example.com:80/path HTTP/1.1"
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    let url = match url::Url::parse(&target) {
        Ok(u) => u,
        Err(_) => {
            let _ = client.write_all(&bad_request("absolute URL required"));
            let _ = client.flush();
            let _ = client.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
    };
    if url.scheme() != "http" {
        let _ = client.write_all(&bad_request("only http:// supported for absolute proxying"));
        let _ = client.flush();
        let _ = client.shutdown(std::net::Shutdown::Both);
        return Ok(());
    }
    let host = match url.host_str() {
        Some(h) => h.to_string(),
        None => {
            let _ = client.write_all(&bad_request("missing host"));
            let _ = client.flush();
            let _ = client.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
    };
    let port = url.port_or_known_default().unwrap_or(80);
    let host_port = format!("{}:{}", host, port);

    let addrs = match checked_addrs(&host_port, corr) {
        Ok(addrs) => addrs,
        Err(e) => {
            let _ = client.write_all(&blocked_response(e.reason(), corr));
            let _ = client.flush();
            let _ = client.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
    };

    let mut upstream = match connect_validated(&addrs) {
        Ok(s) => s,
        Err(err) => {
            let _ = client.write_all(&bad_gateway(&err));
            let _ = client.flush();
            return Ok(());
        }
    };

    // Rebuild the request line in origin form.
    let path = match url.path() {
        "" => "/".to_string(),
        p => p.to_string(),
    };
    let query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();
    let origin = format!("{} {}{} HTTP/1.1\r\n", method, path, query);

    let _ = upstream.write_all(origin.as_bytes());

    // Forward the remaining request headers from the client until the
    // end-of-headers marker (\r\n\r\n), then relay whatever body follows.
    // The request line already consumed "METHOD URL VERSION\r\n".
    let mut buf = [0u8; 8192];
    let mut header_bytes: Vec<u8> = Vec::new();
    let mut body_start: Option<usize> = None;
    loop {
        let n = match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        header_bytes.extend_from_slice(&buf[..n]);
        if let Some(pos) = header_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            body_start = Some(pos + 4);
            break;
        }
        if header_bytes.len() > MAX_LINE * 4 {
            break;
        }
    }
    if let Some(pos) = body_start {
        let headers = &header_bytes[..pos];
        let body = &header_bytes[pos..];
        let rewrite = rewrite_request_headers(headers, &host, port);
        let _ = upstream.write_all(&rewrite);
        let _ = upstream.write_all(body);
    } else {
        let _ = upstream.write_all(&header_bytes);
    }

    // Relay the upstream response back to the client until EOF. The upstream was
    // asked for `Connection: close`, so EOF is the message boundary; a TCP read
    // returning fewer bytes than the buffer is NOT a boundary and must not end
    // the relay. The read timeout bounds a server that never closes.
    let mut resp_buf = [0u8; 8192];
    loop {
        let n = match upstream.read(&mut resp_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if client.write_all(&resp_buf[..n]).is_err() {
            break;
        }
    }

    Ok(())
}

fn handle_client(mut stream: TcpStream) {
    // Bound the client's own reads: a connection that opens and then stays silent
    // must not hold this thread indefinitely.
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let corr = correlation_id();
    let line = match read_line(&mut stream) {
        Ok(l) if !l.is_empty() => l,
        _ => return,
    };

    if let Some(rest) = line.strip_prefix("CONNECT ") {
        let host_port = rest
            .trim_end_matches(" HTTP/1.1")
            .trim_end_matches(" HTTP/1.0")
            .trim();
        let _ = handle_connect(host_port, stream, &corr);
        return;
    }

    if line.starts_with("GET ") || line.starts_with("POST ") || line.starts_with("HEAD ") {
        let _ = handle_absolute(&mut stream, &line, &corr);
        return;
    }

    let _ = stream.write_all(&bad_request("unsupported proxy request"));
}

/// Run the forward-proxy server on 127.0.0.1:<port>.
///
/// # Errors
/// Returns an error string if the listener cannot bind.
pub fn serve(port: u16) -> Result<(), String> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("cannot bind {}: {}", addr, e))?;
    eprintln!("agent-shield forward proxy listening on {}", addr);

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                thread::spawn(move || handle_client(s));
            }
            Err(_) => continue,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_keeps_payloads_parseable() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        assert_eq!(json_escape("\u{1}"), "\\u0001");
    }

    #[test]
    fn rewrite_request_headers_forces_close_and_fixes_host() {
        let headers = b"Host: wrong.example\r\nAccept: */*\r\nConnection: keep-alive\r\n";
        let out =
            String::from_utf8(rewrite_request_headers(headers, "right.example", 8080)).unwrap();
        assert!(out.contains("Host: right.example:8080\r\n"), "{out}");
        assert!(!out.contains("wrong.example"), "{out}");
        assert!(!out.contains("keep-alive"), "{out}");
        assert_eq!(out.matches("Connection:").count(), 1, "{out}");
        assert!(out.contains("Connection: close\r\n"), "{out}");
    }

    #[test]
    fn rewrite_request_headers_appends_host_when_absent() {
        let out = String::from_utf8(rewrite_request_headers(
            b"Accept: */*\r\n",
            "example.com",
            80,
        ))
        .unwrap();
        assert!(out.contains("Host: example.com\r\n"), "{out}");
        assert!(out.contains("Connection: close\r\n"), "{out}");
    }

    #[test]
    fn blocked_response_is_valid_json_with_the_reason_code() {
        let body = String::from_utf8(blocked_response(&BlockReason::SsrfPrivateIp, "abc")).unwrap();
        assert!(body.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert!(
            body.contains("\"reason_code\":\"SSRF_PRIVATE_IP\""),
            "{body}"
        );
        assert!(body.contains("\"correlation_id\":\"abc\""), "{body}");
    }
}
