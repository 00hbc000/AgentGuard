from __future__ import annotations

import html
import json
import logging
import threading
import uuid
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from .orchestrator import scan


_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_LOGGER = logging.getLogger(__name__)


def _validate_public_git_url(source: str) -> None:
    parsed = urlparse(source.strip())
    if parsed.scheme != "https" or parsed.hostname not in {
        "github.com", "gitlab.com", "bitbucket.org",
    }:
        raise ValueError("Only public HTTPS GitHub, GitLab, and Bitbucket URLs are accepted.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Repository URLs must not contain credentials, query strings, or fragments.")


def _run_job(job_id: str, source: str) -> None:
    with _JOBS_LOCK:
        _JOBS[job_id]["status"] = "running"
    try:
        result = scan(source, dynamic=True, force_dynamic=True, include_external=True).to_dict()
    except Exception as exc:
        _LOGGER.exception("Background scan %s failed", job_id)
        with _JOBS_LOCK:
            _JOBS[job_id].update(status="error", error=str(exc))
        return
    with _JOBS_LOCK:
        job_status = "partial" if result.get("scan_status") == "partial" else "complete"
        _JOBS[job_id].update(status=job_status, result=result)


def _create_job(source: str) -> str:
    _validate_public_git_url(source)
    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        _JOBS[job_id] = {"job_id": job_id, "status": "queued", "source": source}
    threading.Thread(target=_run_job, args=(job_id, source), daemon=True).start()
    return job_id


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AgentGuard | Static + Dynamic Review</title>
<style>
:root{--ink:#182328;--muted:#69777a;--paper:#f4f1eb;--panel:#fffefa;--line:#ded8ce;--teal:#126b68;--red:#b52d42;--orange:#c86635;--gold:#b3831f;--green:#287b5f}
*{box-sizing:border-box}body{margin:0;color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;background:radial-gradient(circle at 85% 0,#dbe9e4 0,transparent 35%),var(--paper)}
.shell{max-width:1240px;margin:auto;padding:38px 24px 70px}.mast{display:flex;justify-content:space-between;gap:20px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:25px}.eyebrow{color:var(--teal);font-weight:800;letter-spacing:.12em;text-transform:uppercase;font-size:11px}.mast h1{font:800 clamp(32px,5vw,62px)/.95 Georgia,serif;margin:10px 0 0;letter-spacing:-.03em}.muted{color:var(--muted)}.trust{font-size:12px;color:var(--teal);border:1px solid #a9ccc4;background:#eaf5f1;border-radius:999px;padding:7px 11px;white-space:nowrap}
form{display:flex;gap:10px;margin:28px 0 20px;background:var(--panel);border:1px solid var(--line);padding:10px;border-radius:12px;box-shadow:0 8px 25px #75684b12}input{min-width:0;flex:1;border:0;background:transparent;padding:13px;font:inherit;outline:0}button{border:0;border-radius:8px;background:var(--teal);color:white;font-weight:800;padding:0 20px;cursor:pointer}button:hover{background:#0d504e}
.overview{display:grid;grid-template-columns:1.4fr repeat(4,1fr);gap:12px;margin-top:22px}.hero,.stat,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px}.hero{padding:22px}.hero h2{font:800 30px/1 Georgia,serif;margin:7px 0}.hero p{margin:5px 0}.stat{padding:17px}.stat .value{display:block;font:800 30px Georgia,serif;margin-top:6px}.label{font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.grid{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(280px,.7fr);gap:18px;margin-top:18px}.panel{padding:21px}.panel h3{margin:0 0 15px;font:800 22px Georgia,serif}.bars{display:grid;gap:10px}.barrow{display:grid;grid-template-columns:88px 1fr 35px;gap:10px;align-items:center;font-size:13px}.track{height:9px;background:#e7e1d6;border-radius:99px;overflow:hidden}.fill{height:100%;border-radius:99px}.critical{--accent:var(--red)}.high{--accent:var(--orange)}.medium{--accent:var(--gold)}.low{--accent:var(--green)}.info{--accent:#728186}.fill{background:var(--accent)}
.findings{display:grid;gap:12px}.finding{border:1px solid var(--line);border-left:6px solid var(--accent);border-radius:9px;padding:16px;background:#fff}.finding-head{display:flex;justify-content:space-between;gap:16px;align-items:start;flex-wrap:wrap}.badge{color:var(--accent);font-weight:900;font-size:12px;letter-spacing:.08em;word-break:break-word}.finding h4{margin:8px 0;font-size:17px}.finding p{margin:7px 0}.meta{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted)}details{margin-top:12px;border-top:1px dashed var(--line);padding-top:10px}summary{cursor:pointer;color:var(--teal);font-weight:800;padding:3px 0}.code{white-space:pre-wrap;background:#f5f2ec;border-radius:6px;padding:10px;margin-top:8px;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;overflow:auto}.fingerprint{word-break:break-all}.toollist{display:flex;flex-wrap:wrap;gap:8px}.tool{background:#edf1ef;border:1px solid #d5dfda;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:800}.error{background:#fff0f1;border:1px solid #e5aab2;color:#8e1e31;padding:14px;border-radius:9px;margin-top:20px;white-space:pre-wrap}
@media(max-width:900px){.overview{grid-template-columns:repeat(2,1fr)}.hero{grid-column:span 2}.grid{grid-template-columns:1fr}.mast{align-items:start;flex-direction:column}}@media(max-width:550px){.shell{padding:25px 14px}.overview{display:grid;grid-template-columns:1fr 1fr}form{flex-direction:column}button{height:45px}.hero{grid-column:span 2}}
</style></head><body><main class="shell"><header class="mast"><div><div class="eyebrow">Static + dynamic security review</div><h1>AgentGuard</h1><p class="muted">Static evidence, decision-gate routing, and sandbox observations in one view.</p></div><div class="trust">Skill code runs in isolated Kubernetes</div></header><form id="scan-form" method="post" action="/"><input id="source" name="source" placeholder="Public GitHub, GitLab, or Bitbucket URL" required><button id="submit-scan" type="submit">Run scan</button></form><p id="job-status" class="muted">Static scanning runs first; ambiguous results are routed to the isolated dynamic sandbox.</p><div id="results"></div>{content}</main><script>
document.getElementById("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const source = document.getElementById("source").value.trim();
  const status = document.getElementById("job-status");
  const results = document.getElementById("results");
  const button = document.getElementById("submit-scan");
  let timer;
  let polls = 0;
  button.disabled = true;
  status.textContent = "Queueing scan...";
  results.innerHTML = "";
  try {
    const response = await fetch("/api/jobs", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({source})});
    const job = await response.json();
    if (!response.ok) { throw new Error(job.error || "Could not queue scan."); }
    status.textContent = "Scan queued.";
    timer = setInterval(async () => {
      try {
        polls += 1;
        if (polls > 180) {
          throw new Error("Scan timed out after 3 minutes.");
        }
        const poll = await fetch("/api/jobs/" + job.job_id);
        const current = await poll.json();
        if (!poll.ok) { throw new Error(current.error || "Could not read scan status."); }
        status.textContent = "Scan status: " + current.status;
        if (current.status === "complete" || current.status === "partial") {
          clearInterval(timer);
          results.innerHTML = current.html;
          button.disabled = false;
        } else if (current.status === "error") {
          clearInterval(timer);
          throw new Error(current.error || "Scan failed.");
        }
      } catch (error) {
        clearInterval(timer);
        status.textContent = error.message || "Scan failed.";
        button.disabled = false;
      }
    }, 1000);
  } catch (error) {
    status.textContent = error.message || "Could not queue scan.";
    button.disabled = false;
  }
});
</script></body></html>"""


def _esc(value: object) -> str:
    return html.escape(str(value or ""))


def _render(result: dict) -> str:
    findings = result.get("findings", [])
    severity_counts = Counter(str(item.get("severity", "INFO")).lower() for item in findings)
    tool_counts = Counter(str(item.get("tool", "unknown")) for item in findings)
    max_severity = result.get("aggregate_severity", "INFO")
    status = result.get("scan_status", "unknown")
    tools = result.get("tools_used", [])
    gate = result.get("decision_gate")
    dynamic = result.get("dynamic")
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
    stages = result.get("stages", {})
    stage_cards = "".join(
        f"<div class='tool'><strong>{_esc(name)}</strong>: {_esc(details.get('status', 'unknown'))}"
        f"{' · ' + _esc(details.get('reason')) if details.get('reason') else ''}</div>"
        for name, details in stages.items() if isinstance(details, dict)
    )
    tool_list = "".join(f"<span class='tool'>{_esc(tool)}</span>" for tool in tools) or "<span class='muted'>No scanner completed</span>"
    gate_panel = f"<section class='panel'><h3>Decision gate</h3><p><strong>{'Escalate' if gate.get('escalate') else 'Stop'}</strong></p><p class='muted'>{_esc(gate.get('reason'))}</p></section>" if gate else ""
    dynamic_panel = f"<section class='panel'><h3>Dynamic stage</h3><p><strong>Status:</strong> {_esc(dynamic.get('status'))}</p><p><strong>Monitoring tier:</strong> {_esc(dynamic.get('monitoring_tier'))}</p><p><strong>Dynamic findings:</strong> {_esc(dynamic.get('finding_count'))}</p><p class='muted'>{_esc(dynamic.get('error') or 'No dynamic error')}</p><details><summary>Runtime events</summary><div class='code'>{_esc(json.dumps(dynamic.get('events', []), indent=2))}</div></details></section>" if dynamic else ""
    return f"<section class='overview'><div class='hero'><div class='label'>Verdict</div><h2>{_esc(max_severity)}</h2><p class='muted'>{len(findings)} normalized findings · { _esc(status) }</p></div><div class='stat'><span class='label'>Critical</span><span class='value'>{severity_counts.get('critical',0)}</span></div><div class='stat'><span class='label'>High</span><span class='value'>{severity_counts.get('high',0)}</span></div><div class='stat'><span class='label'>Medium</span><span class='value'>{severity_counts.get('medium',0)}</span></div><div class='stat'><span class='label'>Tools</span><span class='value'>{len(tools)}</span></div></section><section class='panel' style='margin-top:18px'><h3>Pipeline stages</h3><div class='toollist'>{stage_cards or '<span class="muted">No stage data</span>'}</div></section><div class='grid'><section class='panel'><h3>Findings</h3><div class='findings'>{''.join(cards) or '<p class="muted">No findings detected.</p>'}</div></section><aside>{gate_panel}{dynamic_panel}<section class='panel' style='margin-top:18px'><h3>Severity profile</h3><div class='bars'>{bars}</div></section><section class='panel' style='margin-top:18px'><h3>Scanner coverage</h3><div class='toollist'>{tool_list}</div><p class='muted'>{_esc(', '.join(f'{k}: {v}' for k,v in tool_counts.items()))}</p><p class='meta'>Fixture: {_esc(result.get('fixture_id'))}<br>Scan ID: {_esc(result.get('scan_id'))}</p></section></aside></div>"


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: str, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            with _JOBS_LOCK:
                job = dict(_JOBS.get(job_id, {}))
            if not job:
                self._send(json.dumps({"error": "Unknown scan job"}), 404, "application/json")
                return
            if job.get("status") == "complete":
                job["html"] = _render(job["result"])
                job.pop("result", None)
            self._send(json.dumps(job), content_type="application/json")
            return
        if parsed.path == "/api/scan":
            source = parse_qs(parsed.query).get("source", [""])[0]
            try:
                query = parse_qs(parsed.query)
                self._send(json.dumps(scan(
                    source,
                    dynamic=query.get("dynamic", ["0"])[0] == "1",
                    force_dynamic=query.get("force_dynamic", ["0"])[0] == "1",
                    demo_dynamic=query.get("demo_dynamic", ["0"])[0] == "1",
                ).to_dict()), content_type="application/json")
            except Exception as exc:
                self._send(json.dumps({"error": str(exc)}), 400, "application/json")
            return
        self._send(_PAGE.replace("{source}", "").replace("{content}", "<p class='muted'>Enter a local path or GitHub URL to begin.</p>").replace("{dynamic_checked}", "").replace("{force_checked}", "").replace("{demo_checked}", ""))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length).decode("utf-8")
        if self.path == "/api/jobs":
            try:
                payload = json.loads(raw_body)
                job_id = _create_job(str(payload.get("source", "")))
                self._send(json.dumps({"job_id": job_id, "status": "queued"}), 202, "application/json")
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send(json.dumps({"error": str(exc)}), 400, "application/json")
            return
        fields = parse_qs(raw_body)
        source = fields.get("source", [""])[0]
        try:
            result = scan(
                source,
                dynamic="dynamic" in fields,
                force_dynamic="force_dynamic" in fields,
                demo_dynamic="demo_dynamic" in fields,
            ).to_dict()
            page = _PAGE.replace("{source}", _esc(source)).replace("{content}", _render(result))
            page = page.replace("{dynamic_checked}", "checked" if "dynamic" in fields else "")
            page = page.replace("{force_checked}", "checked" if "force_dynamic" in fields else "")
            page = page.replace("{demo_checked}", "checked" if "demo_dynamic" in fields else "")
            self._send(page)
        except Exception as exc:
            page = _PAGE.replace("{source}", _esc(source)).replace("{content}", f"<div class='error'>{_esc(exc)}</div>")
            self._send(page, 400)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    ThreadingHTTPServer((host, port), Handler).serve_forever()
