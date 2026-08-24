//! Forward-proxy server with destination validation.
//!
//! Listens on `127.0.0.1:<port>` and handles absolute-form HTTP requests
//! (`GET http://host/path`) and CONNECT tunnels. Every destination is
//! resolved and validated against the blocked-IP policy BEFORE the
//! connection is opened, so an agent CLI pointed at this proxy cannot
//! reach private, loopback, link-local, or metadata endpoints.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use crate::controlled_fetch::ip_validator::validate_endpoint;
use crate::controlled_fetch::{BlockReason, FetchError};

/// Maximum request-line length we accept (bytes) before rejecting.
const MAX_LINE: usize = 16 * 1024;
/// Correlation id generator using a thread-safe counter + process hint.
fn correlation_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    format!("fwd-{:06x}-{:x}", n, std::process::id())
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
        msg
    )
    .into_bytes()
}

/// Whether this binary honors the AGP_ALLOW_PRIVATE escape (same env var
/// as the fetch path; deliberately shared so tests can flip both).
fn allow_private() -> bool {
    std::env::var("AGP_ALLOW_PRIVATE")
        .map(|v| v == "1")
        .unwrap_or(false)
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

/// Validate an endpoint, honoring the AGP_ALLOW_PRIVATE escape.
fn check_endpoint(host_port: &str, corr: &str) -> Result<(), FetchError> {
    if allow_private() {
        return Ok(());
    }
    validate_endpoint(host_port, corr)
}

/// Handle a CONNECT request: validate destination, reply 200, then tunnel.
fn handle_connect(host_port: &str, mut client: TcpStream, corr: &str) -> std::io::Result<()> {
    if let Err(e) = check_endpoint(host_port, corr) {
        let reason = e.reason();
        let _ = client.write_all(&blocked_response(reason, corr));
        let _ = client.flush();
        let _ = client.shutdown(std::net::Shutdown::Both);
        return Ok(());
    }

    // Drenar los headers del CONNECT hasta CRLFCRLF: el read_line previo
    // consumió solo la request line; los headers restantes vivirían en el
    // socket y, si no se consumen, el túnel los mandaría al upstream como
    // si fueran el primer mensaje TLS (rompe el handshake).
    drain_headers(&mut client)?;

    let upstream = match TcpStream::connect(host_port) {
        Ok(s) => s,
        Err(err) => {
            let body = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
                 {{\"status\":\"error\",\"message\":\"upstream connect failed: {}\"}}",
                err
            );
            let _ = client.write_all(body.as_bytes());
            let _ = client.flush();
            let _ = client.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
    };

    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    let _ = client.flush();

    // Bidirectional tunnel: client -> upstream and upstream -> client.
    let mut upstream = upstream;
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
/// absolute target host, or append one if missing.
fn rewrite_host_header(headers: &[u8], host: &str, port: u16) -> Vec<u8> {
    let host_header = if port == 80 || port == 443 {
        format!("Host: {}", host)
    } else {
        format!("Host: {}:{}", host, port)
    };
    let text = String::from_utf8_lossy(headers);
    let mut out = Vec::with_capacity(headers.len() + 32);
    let mut found = false;
    for (i, line) in text.split_inclusive("\r\n").enumerate() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("host:") {
            out.extend_from_slice(format!("{}\r\n", host_header).as_bytes());
            found = true;
        } else if line == "\r\n" && !found {
            // End of headers with no Host → insert before the blank line.
            out.extend_from_slice(format!("{}\r\n", host_header).as_bytes());
            out.extend_from_slice(line.as_bytes());
            found = true;
        } else {
            out.extend_from_slice(line.as_bytes());
        }
        if i > 64 {
            break;
        }
    }
    // Safety: if no CRLFCRLF was present and nothing matched, add Host at end.
    if !found {
        out.extend_from_slice(format!("{}\r\n", host_header).as_bytes());
    }
    out
}

/// Consume request headers from the client up to and including CRLFCRLF.
/// Bytes beyond the end-of-headers marker are NOT consumed (they belong to
/// the tunnel payload, e.g. a pipelined TLS ClientHello).
fn drain_headers(client: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let n = client.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(());
        }
        if acc.len() > MAX_LINE * 4 {
            return Ok(());
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

    if let Err(e) = check_endpoint(&host_port, corr) {
        let reason = e.reason();
        let _ = client.write_all(&blocked_response(reason, corr));
        let _ = client.flush();
        let _ = client.shutdown(std::net::Shutdown::Both);
        return Ok(());
    }

    let mut upstream = match TcpStream::connect(&host_port) {
        Ok(s) => s,
        Err(err) => {
            let body = format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n\
                 {{\"status\":\"error\",\"message\":\"upstream connect failed: {}\"}}",
                err
            );
            let _ = client.write_all(body.as_bytes());
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
        if n == 0 {
            break;
        }
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
        // Headers end at pos. Rewrite any Host header to the absolute target
        // host (the client one may be wrong/absent for absolute-form).
        let headers = &header_bytes[..pos];
        let body = &header_bytes[pos..];
        let rewrite = rewrite_host_header(headers, &host, port);
        let _ = upstream.write_all(&rewrite);
        let _ = upstream.write_all(body);
    } else {
        let _ = upstream.write_all(&header_bytes);
    }

    // Relay the upstream response back to the client.
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
        if n < 8192 {
            break;
        }
    }

    Ok(())
}

fn handle_client(mut stream: TcpStream) {
    let corr = correlation_id();
    let line = match read_line(&mut stream) {
        Ok(l) if !l.is_empty() => l,
        _ => return,
    };

    if line.starts_with("CONNECT ") {
        let host_port = line
            .trim_start_matches("CONNECT ")
            .trim_end_matches(" HTTP/1.1")
            .trim_end_matches(" HTTP/1.0")
            .trim();
        let _ = handle_connect(host_port, stream, &corr);
        return;
    }

    if line.starts_with("GET ") || line.starts_with("POST ") || line.starts_with("HEAD ") {
        let mut s = stream;
        let _ = handle_absolute(&mut s, &line, &corr);
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
    let _ = listener.set_nonblocking(false);
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
