#!/usr/bin/env python3
"""Harness E2E real para agent-guard-proxy — ejecución del binario release.

Escenarios comprobables SIN allowlist (block_private_ips=true fijo en default):
  A. Fetch a loopback  → debe bloquear con SSRF_PRIVATE_IP (criterio 1 real)
  B. Fetch a link-local → debe bloquear (criterio 1 real)
  C. Fetch a metadata IP → debe bloquear (criterio 1 real)
  D. Redirect inicial bloqueado → no llega al destino (criterio 1+2)
  E. Fetch a IP pública → debe PERMITIR y devolver envelope untrusted
     (prueba transporte HTTP/1.1 real + content filter + envelope)
  F. CLI mal uso → exit 2 sin panic

Además detecta el GAP de testabilidad: sin manera de desactivar el bloqueo
privado, no se puede probar el flujo "permitido" contra un servidor local."""
import http.server
import json
import os
import subprocess
import sys
import threading
import time

BIN = "/home/fxckcode/projects/agent-guard-proxy/target/release/agent-guard-proxy"
PORT = 18765
results = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/ok":
            body = b"contenido normal y confiable"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def start_server(port):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run(url, label, expect, reason=None, exit_expected=None):
    try:
        r = subprocess.run([BIN, "fetch", url], capture_output=True, text=True, timeout=25)
        out = (r.stdout or "").strip()
        ok = False
        if expect == "blocked":
            ok = '"status":"blocked"' in out
            if reason:
                ok = ok and f'"reason_code":"{reason}"' in out
        elif expect == "allowed":
            ok = '"status":"allowed"' in out and '"correlation_id"' in out
            # el envelope debe incluir body y classification
            ok = ok and '"classification"' in out
        elif expect == "exit":
            ok = r.returncode == exit_expected
        results.append((label, "PASS" if ok else "FAIL", out[:180]))
        print(f"[{'PASS' if ok else 'FAIL'}] {label} (exit={r.returncode})")
        print(f"        → {out[:180]}")
    except Exception as e:
        results.append((label, "FAIL", str(e)[:120]))
        print(f"[FAIL] {label}: {e}")


def main():
    if not os.path.exists(BIN):
        print("FATAL: binario no existe; corré cargo build --release primero")
        sys.exit(2)

    srv = start_server(PORT)
    time.sleep(0.4)
    print(f"== Harness E2E agent-guard-proxy ==\n")

    # A: loopback bloqueado antes de conectar (criterio 1)
    run(f"http://127.0.0.1:{PORT}/ok", "A: fetch loopback bloqueado",
        "blocked", "SSRF_PRIVATE_IP")

    # B: link-local (169.254.x.x)
    run("http://169.254.169.254/latest/meta-data", "B: link-local/metadata bloqueado",
        "blocked", "SSRF_PRIVATE_IP")

    # C: rango privado 10.x
    run("http://10.0.0.1/", "C: IP privada 10.x bloqueada",
        "blocked", "SSRF_PRIVATE_IP")

    # D: servidor local con redirect NO se evalúa porque el origen ya es loopback;
    # se prueba que un redirect hacia privado desde host permitido... no hay host
    # permitido local → se valida el bloqueo del origen antes de cualquier hop.
    run(f"http://127.0.0.1:{PORT}/redirect-placeholder", "D: redirect desde origen loopback bloqueado",
        "blocked", "SSRF_PRIVATE_IP")

    # E: IP pública REAL — transporte HTTP/1.1 real + envelope (sin red interna)
    run("http://example.com/", "E: fetch IP pública permitido + envelope",
        "allowed")

    # F: CLI sin url
    r = subprocess.run([BIN, "fetch"], capture_output=True, text=True, timeout=10)
    ok = r.returncode == 2
    results.append(("F: CLI fetch sin URL → exit 2 sin panic",
                    "PASS" if ok else "FAIL", f"exit={r.returncode}"))
    print(f"[{'PASS' if ok else 'FAIL'}] F: CLI fetch sin URL (exit={r.returncode})")

    print("\n== Resumen ==")
    passed = sum(1 for x in results if x[1] == "PASS")
    print(f"{passed}/{len(results)} PASS")
    for label, status, _ in results:
        print(f"  [{status}] {label}")

    print("\n== GAP de testabilidad ==")
    print("FetchPolicy::default() fija block_private_ips=true y el CLI no expone")
    print("ninguna forma de desactivarlo (sin env var, sin flag, sin allowlist).")
    print("Consecuencia: el flujo 'permitido' SOLO se puede probar contra IPs")
    print("públicas reales — no contra fixtures locales (redirects seguros,")
    print("content-types permitidos, prompt-injection en HTML propio).")
    print("Para E2E completo local hace falta un escape: --allow-private-ips")
    print("o AGP_ALLOW_PRIVATE=1 con aviso explícito.")

    srv.shutdown()
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()