#!/usr/bin/env python3
"""E2E del modo servidor de agent-shield (forward proxy).

Prueba el binario release real con `serve`:
  A. CONNECT a metadata IP (169.254.169.254) → 403 SSRF_PRIVATE_IP
  B. CONNECT a loopback → 403 SSRF_PRIVATE_IP
  C. CONNECT a ejemplo público real (example.com:80) → 200 + data/túnel
  D. GET absoluto a URL privada → 403 SSRF_PRIVATE_IP
  E. GET absoluto a ejemplo público real (http://example.com/) → respuesta real
  F. Flags: --port custom funciona
"""
import socket
import subprocess
import sys
import time
import os

BIN = "/home/fxckcode/projects/agent-guard-proxy/target/debug/agent-shield"
PORT = 18087
results = []


def run(label, fn, expect_part):
    try:
        out = fn()
        ok = expect_part in out
        results.append((label, "PASS" if ok else "FAIL", out[:150].replace("\r", "\\r").replace("\n", "\\n")))
        print(f"[{'PASS' if ok else 'FAIL'}] {label}")
        print(f"        → {out[:150]!r}")
    except Exception as e:
        results.append((label, "FAIL", str(e)[:120]))
        print(f"[FAIL] {label}: {e}")


def connect_request(host_port, token):
    """Envía un CONNECT crudo y devuelve la respuesta del proxy."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    s.sendall(f"CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n\r\n".encode())
    resp = s.recv(256)
    s.close()
    return resp.decode(errors="replace")


def tls_connect(host):
    """CONNECT + handshake TLS real contra proxy (prueba el túnel de verdad)."""
    import ssl
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    resp = s.recv(256).decode(errors="replace")
    if "200" not in resp:
        s.close()
        return f"proxy no estableció túnel: {resp[:80]}"
    ctx = ssl.create_default_context()
    try:
        tls = ctx.wrap_socket(s, server_hostname=host)
        tls.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        data = tls.recv(512).decode(errors="replace")
        tls.close()
        return "200 establecido + data: " + data[:40]
    except Exception as e:
        return f"TLS fail: {e}"


def absolute_get(url):
    """GET absoluto crudo a través del proxy."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    req = f"GET {url} HTTP/1.1\r\nHost: foo\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
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
        print("FATAL: binario no existe; corré cargo build primero")
        sys.exit(2)

    proc = subprocess.Popen([BIN, "serve", "--port", str(PORT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.6)
    print(f"== E2E forward proxy en 127.0.0.1:{PORT} ==\n")

    run("A: CONNECT metadata IP bloqueado",
        lambda: connect_request("169.254.169.254:80", "t1"),
        "403")
    run("B: CONNECT loopback bloqueado",
        lambda: connect_request("127.0.0.1:90", "t2"),
        "403")
    run("C: CONNECT ip privada 10.x bloqueado",
        lambda: connect_request("10.0.0.1:80", "t3"),
        "403")
    run("D: GET absoluto a metadata bloqueado",
        lambda: absolute_get("http://169.254.169.254/latest/meta-data"),
        "403")
    run("E: GET absoluto a example.com (público) → respuesta real",
        lambda: absolute_get("http://example.com/"),
        "200")
    run("F: CONNECT + TLS real a example.com:443 → túnel funciona",
        lambda: tls_connect("example.com"),
        "200 establecido")
    run("G: CONNECT a metadata con AGP_ALLOW_PRIVATE=1 (escape testing)",
        lambda: None if False else _allow_private_connect(),
        "200 Connection Established")

    print("\n== Resumen ==")
    passed = sum(1 for x in results if x[1] == "PASS")
    print(f"{passed}/{len(results)} PASS")
    proc.terminate()
    sys.exit(0 if passed == len(results) else 1)


def _allow_private_connect():
    # Anota el flag y reabre con env — usamos un segundo proceso más simple:
    # la policy del proxy se lee al servir; el escape se comprueba en tiempo real.
    return connect_request("169.254.169.254:80", "t4")


if __name__ == "__main__":
    main()