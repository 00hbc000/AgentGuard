from __future__ import annotations

import html
import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from .orchestrator import scan


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentGuard | Static Review</title>
<style>
:root{--ink:#182328;--muted:#69777a;--paper:#f4f1eb;--panel:#fffefa;--line:#ded8ce;--teal:#126b68;--red:#b52d42;--orange:#c86635;--gold:#b3831f;--green:#287b5f}
*{box-sizing:border-box}body{margin:0;color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;background:radial-gradient(circle at 85% 0,#dbe9e4 0,transparent 35%),var(--paper)}
.shell{max-width:1240px;margin:auto;padding:38px 24px 70px}.mast{display:flex;justify-content:space-between;gap:20px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:25px}.eyebrow{color:var(--teal);font-weight:800;letter-spacing:.12em;text-transform:uppercase;font-size:11px}.mast h1{font:800 clamp(32px,5vw,62px)/.95 Georgia,serif;margin:10px 0 0;letter-spacing:-.03em}.muted{color:var(--muted)}.trust{font-size:12px;color:var(--teal);border:1px solid #a9ccc4;background:#eaf5f1;border-radius:999px;padding:7px 11px;white-space:nowrap}
form{display:flex;gap:10px;margin:28px 0 20px;background:var(--panel);border:1px solid var(--line);padding:10px;border-radius:12px;box-shadow:0 8px 25px #75684b12}input{min-width:0;flex:1;border:0;background:transparent;padding:13px;font:inherit;outline:0}button{border:0;border-radius:8px;background:var(--teal);color:white;font-weight:800;padding:0 20px;cursor:pointer}button:hover{background:#0d504e}
.overview{display:grid;grid-template-columns:1.4fr repeat(4,1fr);gap:12px;margin-top:22px}.hero,.stat,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px}.hero{padding:22px}.hero h2{font:800 30px/1 Georgia,serif;margin:7px 0}.hero p{margin:5px 0}.stat{padding:17px}.stat .value{display:block;font:800 30px Georgia,serif;margin-top:6px}.label{font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.grid{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(280px,.7fr);gap:18px;margin-top:18px}.panel{padding:21px}.panel h3{margin:0 0 15px;font:800 22px Georgia,serif}.bars{display:grid;gap:10px}.barrow{display:grid;grid-template-columns:88px 1fr 35px;gap:10px;align-items:center;font-size:13px}.track{height:9px;background:#e7e1d6;border-radius:99px;overflow:hidden}.fill{height:100%;border-radius:99px}.critical{--accent:var(--red)}.high{--accent:var(--orange)}.medium{--accent:var(--gold)}.low{--accent:var(--green)}.info{--accent:#728186}.fill{background:var(--accent)}
.findings{display:grid;gap:12px}.finding{border:1px solid var(--line);border-left:6px solid var(--accent);border-radius:9px;padding:16px;background:#fff}.finding-head{display:flex;justify-content:space-between;gap:10px;align-items:start}.badge{color:var(--accent);font-weight:900;font-size:12px;letter-spacing:.08em}.finding h4{margin:6px 0;font-size:17px}.finding p{margin:5px 0}.meta{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted)}details{margin-top:12px;border-top:1px dashed var(--line);padding-top:10px}summary{cursor:pointer;color:var(--teal);font-weight:800}.code{white-space:pre-wrap;background:#f5f2ec;border-radius:6px;padding:10px;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;overflow:auto}.fingerprint{word-break:break-all}.toollist{display:flex;flex-wrap:wrap;gap:8px}.tool{background:#edf1ef;border:1px solid #d5dfda;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:800}.error{background:#fff0f1;border:1px solid #e5aab2;color:#8e1e31;padding:14px;border-radius:9px;margin-top:20px;white-space:pre-wrap}
@media(max-width:900px){.overview{grid-template-columns:repeat(2,1fr)}.hero{grid-column:span 2}.grid{grid-template-columns:1fr}.mast{align-items:start;flex-direction:column}}@media(max-width:550px){.shell{padding:25px 14px}.overview{display:grid;grid-template-columns:1fr 1fr}form{flex-direction:column}button{height:45px}.hero{grid-column:span 2}}
</style></head><body><main class="shell"><header class="mast"><div><div class="eyebrow">Static security review</div><h1>AgentGuard</h1><p class="muted">One evidence-rich view across Cisco, NVIDIA, and native gap rules.</p></div><div class="trust">No skill execution</div></header><form method="post"><input name="source" value="{source}" placeholder="Local skill directory, archive, or GitHub URL" required><button type="submit">Run static scan</button></form>{content}</main></body></html>"""


def _esc(value: object) -> str:
    return html.escape(str(value or ""))


def _render(result: dict) -> str:
    findings = result.get("findings", [])
    severity_counts = Counter(str(item.get("severity", "INFO")).lower() for item in findings)
    tool_counts = Counter(str(item.get("tool", "unknown")) for item in findings)
    max_severity = result.get("aggregate_severity", "INFO")
    status = result.get("scan_status", "unknown")
    tools = result.get("tools_used", [])
    cards = []
    for item in findings:
        severity = str(item.get("severity", "INFO")).lower()
        path = item.get("file_path") or "package"
        if item.get("line_number"):
            path += f":{item['line_number']}"
        evidence = item.get("evidence")
        details = ""
        if evidence:
            details += f"<details><summary>Evidence</summary><div class='code'>{_esc(evidence)}</div></details>"
        raw = item.get("raw") or {}
        if raw:
            details += f"<details><summary>Raw { _esc(item.get('tool')) } finding</summary><div class='code'>{_esc(json.dumps(raw, indent=2))}</div></details>"
        cards.append(f"<article class='finding {severity}'><div class='finding-head'><span class='badge'>{_esc(severity)} · {_esc(item.get('tool'))} · {_esc(item.get('rule_id'))}</span><span class='meta'>{_esc(path)}</span></div><h4>{_esc(item.get('message') or 'Finding')}</h4><p>{_esc(item.get('description'))}</p><p class='meta'>Confidence: {_esc(item.get('confidence') if item.get('confidence') is not None else 'not provided')} · Fingerprint: <span class='fingerprint'>{_esc(item.get('fingerprint'))}</span></p><p><strong>Remediation:</strong> {_esc(item.get('remediation'))}</p>{details}</article>")
    max_count = max(severity_counts.values(), default=1)
    bars = "".join(f"<div class='barrow'><span>{_esc(level.upper())}</span><div class='track'><div class='fill {level}' style='width:{round(severity_counts.get(level,0)/max_count*100)}%'></div></div><strong>{severity_counts.get(level,0)}</strong></div>" for level in ("critical","high","medium","low","info"))
    tool_list = "".join(f"<span class='tool'>{_esc(tool)}</span>" for tool in tools) or "<span class='muted'>No scanner completed</span>"
    return f"<section class='overview'><div class='hero'><div class='label'>Verdict</div><h2>{_esc(max_severity)}</h2><p class='muted'>{len(findings)} normalized findings · { _esc(status) }</p></div><div class='stat'><span class='label'>Critical</span><span class='value'>{severity_counts.get('critical',0)}</span></div><div class='stat'><span class='label'>High</span><span class='value'>{severity_counts.get('high',0)}</span></div><div class='stat'><span class='label'>Medium</span><span class='value'>{severity_counts.get('medium',0)}</span></div><div class='stat'><span class='label'>Tools</span><span class='value'>{len(tools)}</span></div></section><div class='grid'><section class='panel'><h3>Findings</h3><div class='findings'>{''.join(cards) or '<p class="muted">No findings detected.</p>'}</div></section><aside><section class='panel'><h3>Severity profile</h3><div class='bars'>{bars}</div></section><section class='panel' style='margin-top:18px'><h3>Scanner coverage</h3><div class='toollist'>{tool_list}</div><p class='muted'>{_esc(', '.join(f'{k}: {v}' for k,v in tool_counts.items()))}</p><p class='meta'>Fixture: {_esc(result.get('fixture_id'))}<br>Scan ID: {_esc(result.get('scan_id'))}</p></section></aside></div>"


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            source = parse_qs(parsed.query).get("source", [""])[0]
            try:
                self._send(json.dumps(scan(source).to_dict()), content_type="application/json")
            except Exception as exc:
                self._send(json.dumps({"error": str(exc)}), 400, "application/json")
            return
        self._send(_PAGE.replace("{source}", "").replace("{content}", "<p class='muted'>Enter a local path or GitHub URL to begin.</p>"))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        source = parse_qs(self.rfile.read(length).decode("utf-8")).get("source", [""])[0]
        try:
            result = scan(source).to_dict()
            page = _PAGE.replace("{source}", _esc(source)).replace("{content}", _render(result))
            self._send(page)
        except Exception as exc:
            page = _PAGE.replace("{source}", _esc(source)).replace("{content}", f"<div class='error'>{_esc(exc)}</div>")
            self._send(page, 400)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    ThreadingHTTPServer((host, port), Handler).serve_forever()
