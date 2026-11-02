from __future__ import annotations

import json
import os
from urllib.parse import urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer


class SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        event = {
            "type": "network_sink",
            "path": self.path,
            "bytes": len(body),
            "source": self.client_address[0],
            "scan_token": urlparse(self.path).path.rsplit("/", 1)[-1] or None,
        }
        print(json.dumps(event), flush=True)
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), SinkHandler).serve_forever()
