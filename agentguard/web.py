from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from pathlib import Path

from .orchestrator import scan


_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>AgentGuard</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#17202a;background:#f4f7f6}
h1{margin-bottom:4px}.muted{color:#647277}form{display:flex;gap:8px;margin:24px 0}input{flex:1;padding:12px;border:1px solid #b8c5c7;border-radius:6px}button{padding:12px 18px;border:0;border-radius:6px;background:#146c6e;color:white;font-weight:700}section{background:white;border:1px solid #dbe3e4;border-radius:8px;padding:20px;margin-top:20px}.finding{border-left:5px solid #9aa; padding:12px 16px;margin:12px 0;background:#fbfcfc}.critical{border-color:#a62639}.high{border-color:#d45b37}.medium{border-color:#c99425}.low{border-color:#378c72}.tag{font-size:12px;font-weight:700;text-transform:uppercase;color:#59666a}.error{color:#a62639;white-space:pre-wrap}
</style></head><body><h1>AgentGuard</h1><p class="muted">Static skill security findings, normalized across scanners.</p>
<form method="post"><input name="source" placeholder="Local skill directory, archive, or GitHub URL" required><button>Scan</button></form>{content}</body></html>"""


def _render(result: dict) -> str:
    findings = result.get("findings", [])
    cards = []
    for item in findings:
        location = item.get("location", {})
        where = location.get("path") or "package"
        if location.get("start_line"):
            where += f":{location['start_line']}"
        cards.append(
            f"<article class='finding {html.escape(item.get('severity','info'))}'>"
            f"<div class='tag'>{html.escape(item.get('severity','info'))} · {html.escape(item.get('tool',''))} · {html.escape(item.get('rule_id') or '')}</div>"
            f"<h3>{html.escape(item.get('message','Finding'))}</h3>"
            f"<p>{html.escape(item.get('description') or '')}</p>"
            f"<p class='muted'>{html.escape(where)}</p></article>"
        )
    return f"<section><strong>{len(findings)} normalized finding(s)</strong><p class='muted'>Scan {html.escape(result.get('scan_id',''))}</p>{''.join(cards) or '<p>No findings.</p>'}</section>"


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/api/scan":
            source = parse_qs(urlparse(self.path).query).get("source", [""])[0]
            try:
                result = scan(source).to_dict()
                self._send(json.dumps(result), content_type="application/json")
            except Exception as exc:
                self._send(json.dumps({"error": str(exc)}), 400, "application/json")
            return
        self._send(_PAGE.format(content=""))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        data = parse_qs(self.rfile.read(length).decode("utf-8"))
        source = data.get("source", [""])[0]
        try:
            result = scan(source).to_dict()
            self._send(_PAGE.format(content=_render(result)))
        except Exception as exc:
            self._send(_PAGE.format(content=f"<section class='error'>{html.escape(str(exc))}</section>"), 400)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    ThreadingHTTPServer((host, port), Handler).serve_forever()
