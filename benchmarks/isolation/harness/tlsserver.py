"""Loopback TLS server for the ``https_loopback`` workload family.

The server runs in the harness process, outside whatever confinement the
launcher applies, because it stands in for a remote API that a confined agent
reaches out to. Loopback rather than a public endpoint so the family measures
the socket and TLS cost of confinement instead of WAN variance — the same
reason its payload size is fixed.
"""

from __future__ import annotations

import http.server
import os
import ssl
import subprocess
import threading
from typing import Any

#: Fixed response body size. Large enough that read() does real work, small
#: enough that the family is not measuring memcpy throughput.
PAYLOAD = b"x" * 4096


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence per-request logging; it would be the loudest cost in the loop."""


class LoopbackTlsServer:
    """Self-signed TLS server bound to an ephemeral loopback port."""

    def __init__(self, workdir: str) -> None:
        self.workdir = workdir
        self.cert_path = os.path.join(workdir, "aabench-cert.pem")
        self.key_path = os.path.join(workdir, "aabench-key.pem")
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.url: str | None = None

    def _generate_cert(self) -> None:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                self.key_path,
                "-out",
                self.cert_path,
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )

    def start(self) -> None:
        self._generate_cert()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_path, self.key_path)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        self._server = server
        self.url = f"https://127.0.0.1:{server.server_address[1]}/payload"
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    def client_env(self) -> dict[str, str]:
        if self.url is None:
            raise RuntimeError("server not started")
        return {"AABENCH_HTTPS_URL": self.url, "AABENCH_HTTPS_CA": self.cert_path}
