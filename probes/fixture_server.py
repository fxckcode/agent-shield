#!/usr/bin/env python3
"""Fixture HTTP local persistente para pruebas de integración de agent-shield."""
import http.server
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18091


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b'{"ok": true, "data": "AGENT TRAFFIC THROUGH SHIELD", "source": "fixture-local"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"fixture en 127.0.0.1:{PORT}")
    srv.serve_forever()