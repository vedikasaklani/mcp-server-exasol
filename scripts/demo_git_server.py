"""Serve a directory of bare git repositories over smart HTTP.

Exists so the full production path - clone, shallow-fetch an exact commit,
install dependencies, profile, confine, serve - can be demonstrated and
regression-tested without real GitHub credentials or network access. Point
the Warden runner at it with WARDEN_GIT_BASE_URL.

    python3 scripts/demo_git_server.py <repo-root> [port]

Development fixture only: no auth, no TLS, binds to loopback.
"""
from __future__ import annotations

import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.abspath(sys.argv[1])
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9500


class Handler(BaseHTTPRequestHandler):
    def _serve(self, body: bytes = b"") -> None:
        path, _, query = self.path.partition("?")
        env = {
            "GIT_PROJECT_ROOT": ROOT,
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": self.command,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "REMOTE_ADDR": self.client_address[0],
            "PATH": os.environ["PATH"],
            "HTTP_CONTENT_ENCODING": self.headers.get("Content-Encoding", ""),
        }
        proc = subprocess.run(
            ["git", "http-backend"], input=body, env=env, capture_output=True
        )
        head, _, payload = proc.stdout.partition(b"\r\n\r\n")
        status = 200
        headers = []
        for line in head.split(b"\r\n"):
            if not line:
                continue
            key, _, value = line.partition(b": ")
            if key.lower() == b"status":
                status = int(value.split()[0])
            else:
                headers.append((key.decode(), value.decode()))
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._serve(self.rfile.read(int(self.headers.get("Content-Length", 0))))

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    try:
        server = HTTPServer(("127.0.0.1", PORT), Handler)
    except OSError as exc:
        if exc.errno != 98:  # EADDRINUSE
            raise
        # Almost always this same fixture already running, which is fine:
        # it reads the repositories from disk per request, so a rebuild is
        # picked up without a restart. Say that rather than a traceback.
        print(f"port {PORT} is already in use - if that is this fixture, "
              f"it is already serving {ROOT} and needs no restart.")
        print(f"check with: curl -s -o /dev/null -w '%{{http_code}}\\n' "
              f"'http://127.0.0.1:{PORT}/demo/mcp.git/info/refs?service=git-upload-pack'")
        raise SystemExit(1)
    print(f"serving git repositories under {ROOT} on http://127.0.0.1:{PORT}")
    server.serve_forever()
