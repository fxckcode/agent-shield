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
import threading
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


def connect_request_to(host_port, token, port):
    """Envía un CONNECT crudo a un puerto específico del proxy."""
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(f"CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n\r\n".encode())
    resp = s.recv(256)
    s.close()
    return resp.decode(errors="replace")


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
    # El proxy se arranca con AGP_ALLOW_PRIVATE SOLO para el test G (escape).
    # Tests A-F requieren el bloqueo activo → usamos un server SIN el flag para
    # casi todo, y un segundo server CON el flag para G.
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
    run("D: GET absoluto a metadata bloqueado (403 limpio, sin reset)",
        lambda: absolute_get("http://169.254.169.254/latest/meta-data"),
        "403")
    run("E: GET absoluto a example.com (público) → respuesta real",
        lambda: absolute_get("http://example.com/"),
        "200")
    run("F: CONNECT + TLS real a example.com:443 → túnel funciona",
        lambda: tls_connect("example.com"),
        "200 establecido")

    # G: server con AGP_ALLOW_PRIVATE=1 → el escape permite el loopback y el
    # CONNECT a un servidor local responde 200 (túnel real al fixture).
    proc_allow = subprocess.Popen([BIN, "serve", "--port", str(PORT + 1)],
                                  env=dict(os.environ, AGP_ALLOW_PRIVATE="1"),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.6)

    # levantar un servidor HTTP simple en 127.0.0.1:19099 como fixture
    import http.server
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 19099),
                                          http.server.BaseHTTPRequestHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)

    def _g_check():
        # CONNECT loopback al fixture: sin flag daría 403; con flag responde 200
        # (y el túnel queda abierto hacia el server local).
        s = socket.create_connection(("127.0.0.1", PORT + 1), timeout=10)
        s.sendall(b"CONNECT 127.0.0.1:19099 HTTP/1.1\r\nHost: 127.0.0.1:19099\r\n\r\n")
        resp = s.recv(256)
        s.close()
        return resp.decode(errors="replace")

    run("G: CONNECT loopback con AGP_ALLOW_PRIVATE=1 (escape testing)",
        _g_check,
        "200 Connection Established")
    srv.shutdown()

    print("\n== Resumen ==")
    passed = sum(1 for x in results if x[1] == "PASS")
    print(f"{passed}/{len(results)} PASS")
    proc.terminate()
    proc_allow.terminate()
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()