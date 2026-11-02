from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import canary  # noqa: E402  (copied next to this file in the sink image)

MAX_BODY = 1024 * 1024


def build_event(method: str, path: str, headers: dict[str, str], body: bytes, source: str) -> dict:
    """Describe one request the sandboxed skill sent to the controlled sink.

    ``canary_hits`` is the authoritative exfiltration proof: it means a honeypot
    secret planted for a specific scan reached the network, whatever encoding was used.
    """
    haystack = b"\n".join([
        path.encode("utf-8", errors="replace"),
        "\n".join(f"{k}: {v}" for k, v in headers.items()).encode("utf-8", errors="replace"),
        body,
    ])
    hits = canary.find_canaries(haystack)
    token = urlparse(path).path.rstrip("/").rsplit("/", 1)[-1] or None
    return {
        "type": "network_sink",
        "method": method,
        "path": path,
        "host": headers.get("Host"),
        "user_agent": headers.get("User-Agent"),
        "bytes": len(body),
        "source": source,
        "scan_token": token,
        "canary_hits": hits,
        "body_preview": body[:160].decode("utf-8", errors="replace"),
    }


class SinkHandler(BaseHTTPRequestHandler):
    def _handle(self) -> None:
        try:
            length = min(int(self.headers.get("Content-Length", "0") or 0), MAX_BODY)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        headers = {key: value for key, value in self.headers.items()}
        print(json.dumps(build_event(self.command, self.path, headers, body, self.client_address[0])), flush=True)
        self.send_response(204)
        self.end_headers()

    do_POST = do_PUT = do_PATCH = do_GET = do_DELETE = _handle

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), SinkHandler).serve_forever()
