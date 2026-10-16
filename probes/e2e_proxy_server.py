#!/usr/bin/env python3
"""End-to-end harness for agent-shield's forward-proxy mode (`serve`).

Runs the real binary and drives it with raw sockets:
  A. CONNECT to a metadata address            -> 403 SSRF_PRIVATE_IP
  B. CONNECT to loopback                      -> 403 SSRF_PRIVATE_IP
  C. CONNECT to an RFC 1918 address           -> 403 SSRF_PRIVATE_IP
  D. absolute-form GET to a metadata address  -> 403, a clean response and no reset
  E. absolute-form GET to a public host       -> a real response
  F. CONNECT + real TLS handshake to a public host -> the tunnel works
  G. CONNECT to loopback with AGP_ALLOW_PRIVATE=1 -> 200, the testing escape

F and E need real outbound network. A-D and G do not.
"""
import http.server
import os
import socket
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get(
    "AGENT_SHIELD_BIN", os.path.join(REPO, "target", "release", "agent-shield")
)
PORT = 18087
PROXY = "127.0.0.1"
results = []


def run(label, fn, expect_part):
    try:
        out = fn()
        ok = expect_part in out
        results.append(
            (label, "PASS" if ok else "FAIL", out[:150].replace("\r", "\\r").replace("\n", "\\n"))
        )
        print(f"[{'PASS' if ok else 'FAIL'}] {label}")
        print(f"        -> {out[:150]!r}")
    except Exception as e:  # noqa: BLE001 - report any harness failure
        results.append((label, "FAIL", str(e)[:120]))
        print(f"[FAIL] {label}: {e}")


def connect_request(host_port, port=PORT):
    """Send a raw CONNECT to the proxy and return its response."""
    s = socket.create_connection((PROXY, port), timeout=10)
    s.sendall(f"CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n\r\n".encode())
    resp = s.recv(256)
    s.close()
    return resp.decode(errors="replace")


def tls_connect(host):
    """CONNECT, then a real TLS handshake through it, to prove the tunnel carries traffic."""
    import ssl

    s = socket.create_connection((PROXY, PORT), timeout=10)
    s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    resp = s.recv(256).decode(errors="replace")
    if "200" not in resp:
        s.close()
        return f"proxy did not establish a tunnel: {resp[:80]}"
    ctx = ssl.create_default_context()
    try:
        tls = ctx.wrap_socket(s, server_hostname=host)
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = tls.recv(512).decode(errors="replace")
        tls.close()
        return "200 established + data: " + data[:40]
    except Exception as e:  # noqa: BLE001 - reported as a harness failure
        return f"TLS fail: {e}"


def absolute_get(url, port=PORT):
    """Raw absolute-form GET through the proxy."""
    s = socket.create_connection((PROXY, port), timeout=10)
    s.sendall(f"GET {url} HTTP/1.1\r\nHost: foo\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        try:
            chunk = s.recv(1024)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    s.close()
    return data.decode(errors="replace")


def main():
    if not os.path.exists(BIN):
        print(f"FATAL: binary not found at {BIN}; run `cargo build --release` first")
        sys.exit(2)

    # A-F need the block active, so this instance runs without the escape.
    proc = subprocess.Popen(
        [BIN, "serve", "--port", str(PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.6)
    print(f"== forward-proxy E2E on {PROXY}:{PORT} ==\n")

    run("A: CONNECT to a metadata address blocked",
        lambda: connect_request("169.254.169.254:80"), "403")
    run("B: CONNECT to loopback blocked",
        lambda: connect_request("127.0.0.1:90"), "403")
    run("C: CONNECT to an RFC 1918 address blocked",
        lambda: connect_request("10.0.0.1:80"), "403")
    run("D: absolute-form GET to a metadata address blocked (clean 403, no reset)",
        lambda: absolute_get("http://169.254.169.254/latest/meta-data"), "403")
    run("E: absolute-form GET to a public host returns a real response",
        lambda: absolute_get("http://example.com/"), "200")
    run("F: CONNECT + real TLS to a public host (the tunnel carries traffic)",
        lambda: tls_connect("example.com"), "200 established")

    # G: a second instance WITH the escape, to show it reaches a local fixture.
    proc_allow = subprocess.Popen(
        [BIN, "serve", "--port", str(PORT + 1)],
        env=dict(os.environ, AGP_ALLOW_PRIVATE="1"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.6)

    fixture = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 19099), http.server.BaseHTTPRequestHandler
    )
    fixture.daemon_threads = True
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    time.sleep(0.3)

    run("G: CONNECT to loopback with AGP_ALLOW_PRIVATE=1 (testing escape)",
        lambda: connect_request("127.0.0.1:19099", port=PORT + 1),
        "200 Connection Established")
    fixture.shutdown()

    print("\n== Summary ==")
    passed = sum(1 for x in results if x[1] == "PASS")
    print(f"{passed}/{len(results)} PASS")
    proc.terminate()
    proc_allow.terminate()
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
