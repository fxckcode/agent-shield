#!/usr/bin/env python3
"""End-to-end harness for agent-shield, run against the release binary.

Scenarios that are checkable with the default policy (block_private_ips=true):
  A. Fetch to loopback  -> blocked with SSRF_PRIVATE_IP
  B. Fetch to link-local / metadata -> blocked
  C. Fetch to an RFC 1918 address -> blocked
  D. Fetch whose origin is loopback -> blocked before any redirect hop
  E. Fetch to a public address -> allowed, returns the untrusted envelope
  F. CLI misuse -> exit 2 without a panic

With AGP_ALLOW_PRIVATE=1 the same destinations reach a local fixture, which is
how the allowed path is exercised without leaving the machine (see e2e_full.py).
"""
import http.server
import os
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get(
    "AGENT_SHIELD_BIN", os.path.join(REPO, "target", "release", "agent-shield")
)
PORT = 18765
results = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/ok":
            body = b"ordinary trusted-looking content"
            self.send_response(200)
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


def run(url, label, expect, reason=None, exit_expected=None, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    try:
        r = subprocess.run(
            [BIN, "fetch", url], capture_output=True, text=True, timeout=25, env=env
        )
        out = (r.stdout or "").strip()
        ok = False
        if expect == "blocked":
            ok = '"status":"blocked"' in out
            if reason:
                ok = ok and f'"reason_code":"{reason}"' in out
        elif expect == "allowed":
            # The envelope must carry the body and its classification.
            ok = (
                '"status":"allowed"' in out
                and '"correlation_id"' in out
                and '"classification"' in out
            )
        elif expect == "exit":
            ok = r.returncode == exit_expected
        results.append((label, "PASS" if ok else "FAIL", out[:180]))
        print(f"[{'PASS' if ok else 'FAIL'}] {label} (exit={r.returncode})")
        print(f"        -> {out[:180]}")
    except Exception as e:  # noqa: BLE001 - report any harness failure
        results.append((label, "FAIL", str(e)[:120]))
        print(f"[FAIL] {label}: {e}")


def main():
    if not os.path.exists(BIN):
        print(f"FATAL: binary not found at {BIN}; run `cargo build --release` first")
        sys.exit(2)

    srv = start_server(PORT)
    time.sleep(0.4)
    print("== agent-shield E2E harness ==\n")

    # A: loopback is refused before any connection is attempted.
    run(
        f"http://127.0.0.1:{PORT}/ok",
        "A: fetch to loopback blocked",
        "blocked",
        "SSRF_PRIVATE_IP",
    )

    # B: link-local, which includes the cloud metadata address.
    run(
        "http://169.254.169.254/latest/meta-data",
        "B: link-local/metadata blocked",
        "blocked",
        "SSRF_PRIVATE_IP",
    )

    # C: RFC 1918.
    run("http://10.0.0.1/", "C: RFC 1918 address blocked", "blocked", "SSRF_PRIVATE_IP")

    # D: a redirect away from a blocked origin never gets evaluated, because the
    # origin policy rejects the request before the first hop.
    run(
        f"http://127.0.0.1:{PORT}/redirect-placeholder",
        "D: loopback origin blocked before any hop",
        "blocked",
        "SSRF_PRIVATE_IP",
    )

    # E: a real public address, exercising the HTTP/1.1 transport and the envelope.
    run("http://example.com/", "E: public fetch allowed + envelope", "allowed")

    # F: the CLI rejects a missing URL without panicking.
    r = subprocess.run([BIN, "fetch"], capture_output=True, text=True, timeout=10)
    ok = r.returncode == 2
    results.append(
        ("F: fetch with no URL exits 2 without panic", "PASS" if ok else "FAIL", f"exit={r.returncode}")
    )
    print(f"[{'PASS' if ok else 'FAIL'}] F: fetch with no URL (exit={r.returncode})")

    print("\n== Summary ==")
    passed = sum(1 for x in results if x[1] == "PASS")
    print(f"{passed}/{len(results)} PASS")
    for label, status, _ in results:
        print(f"  [{status}] {label}")

    print("\n== Local fixture path ==")
    print("AGP_ALLOW_PRIVATE=1 disables the private-IP block and prints a warning,")
    print("which is what makes the allowed flow testable against a local fixture")
    print("instead of only against real public addresses. Never use it in production.")

    srv.shutdown()
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
