"""AgentGuard dashboard: Quick / Sandbox / Deep scans, batch scanning, history and report download.

Standard library only. Scans run as durable subprocess jobs (see :mod:`agentguard.jobs`).
Written to parse on Python 3.11 as well as 3.12+ (no nested same-quote f-strings).
"""
from __future__ import annotations

import csv
import html
import io
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import samples as sample_library
from . import scanners
from .jobs import ID_PATTERN, REPO_ROOT, JobStore, validate_public_git_url
from .report_html import render_report

_LOGGER = logging.getLogger(__name__)
MAX_BODY = 64 * 1024

_STYLE = """
:root{--ink:#182328;--muted:#69777a;--paper:#f4f1eb;--panel:#fffefa;--line:#ded8ce;--teal:#126b68;--red:#b52d42;--orange:#c86635;--gold:#b3831f;--green:#287b5f}
*{box-sizing:border-box}body{margin:0;color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;background:radial-gradient(circle at 85% 0,#dbe9e4 0,transparent 35%),var(--paper)}
.shell{max-width:1240px;margin:auto;padding:30px 24px 70px}.mast{display:flex;justify-content:space-between;gap:20px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:20px}.eyebrow{color:var(--teal);font-weight:800;letter-spacing:.12em;text-transform:uppercase;font-size:11px}.mast h1{font:800 clamp(30px,5vw,54px)/.95 Georgia,serif;margin:8px 0 0;letter-spacing:-.03em}.muted{color:var(--muted)}.trust{font-size:12px;color:var(--teal);border:1px solid #a9ccc4;background:#eaf5f1;border-radius:999px;padding:7px 11px;white-space:nowrap}
nav{display:flex;gap:6px;margin:16px 0 0}nav a{padding:7px 14px;border-radius:8px;color:var(--ink);text-decoration:none;font-weight:700;font-size:14px;border:1px solid transparent}nav a.active{background:var(--teal);color:#fff}nav a:hover:not(.active){border-color:var(--line);background:var(--panel)}
form.scan{display:flex;gap:10px;margin:22px 0 10px;background:var(--panel);border:1px solid var(--line);padding:10px;border-radius:12px;box-shadow:0 8px 25px #75684b12;flex-wrap:wrap}input[type=text],textarea,select{min-width:0;border:1px solid var(--line);background:#fff;padding:11px;font:inherit;outline:0;border-radius:8px}form.scan input[type=text]{flex:1 1 360px}textarea{width:100%;font:13px ui-monospace,Consolas,monospace}
button,a.btn{border:0;border-radius:8px;background:var(--teal);color:white;font-weight:800;padding:10px 18px;cursor:pointer;text-decoration:none;display:inline-block;font-size:14px}button:hover,a.btn:hover{background:#0d504e}button:disabled{opacity:.5;cursor:default}button.ghost,a.ghost{background:#fff;color:var(--teal);border:1px solid var(--teal)}button.danger{background:var(--red)}
.overview{display:grid;grid-template-columns:1.6fr repeat(4,1fr);gap:12px;margin-top:22px}.hero,.stat,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px}.hero{padding:22px;border-left:8px solid var(--accent,#728186)}.hero h2{font:800 28px/1.05 Georgia,serif;margin:7px 0}.hero p{margin:5px 0}.stat{padding:17px}.stat .value{display:block;font:800 30px Georgia,serif;margin-top:6px}.label{font-size:11px;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.grid{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(300px,.8fr);gap:18px;margin-top:18px}.panel{padding:21px}.panel h3{margin:0 0 15px;font:800 21px Georgia,serif}.modes{display:flex;gap:8px;flex-wrap:wrap;padding:6px 0 2px;width:100%}.mode{display:flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:8px;padding:8px 11px;background:#faf8f3;font-size:13px}.mode:has(input:checked){border-color:var(--teal);background:#eaf5f1;color:var(--teal);font-weight:800}.bars{display:grid;gap:10px}.barrow{display:grid;grid-template-columns:88px 1fr 35px;gap:10px;align-items:center;font-size:13px}.track{height:9px;background:#e7e1d6;border-radius:99px;overflow:hidden}.fill{height:100%;border-radius:99px}
.critical{--accent:var(--red)}.high{--accent:var(--orange)}.medium{--accent:var(--gold)}.low{--accent:var(--green)}.info{--accent:#728186}.fill{background:var(--accent)}
.findings{display:grid;gap:12px}.finding{border:1px solid var(--line);border-left:6px solid var(--accent);border-radius:9px;padding:16px;background:#fff}.finding-head{display:flex;justify-content:space-between;gap:16px;align-items:start;flex-wrap:wrap}.badge{color:var(--accent);font-weight:900;font-size:12px;letter-spacing:.08em;word-break:break-word}.finding h4{margin:8px 0;font-size:17px}.finding p{margin:7px 0}.meta{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted)}details{margin-top:12px;border-top:1px dashed var(--line);padding-top:10px}summary{cursor:pointer;color:var(--teal);font-weight:800;padding:3px 0}.code{white-space:pre-wrap;background:#f5f2ec;border-radius:6px;padding:10px;margin-top:8px;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;overflow:auto;max-height:420px}.fingerprint{word-break:break-all}
.toollist{display:flex;flex-wrap:wrap;gap:8px}.tool{background:#edf1ef;border:1px solid #d5dfda;border-radius:999px;padding:6px 10px;font-size:12px;font-weight:800}.tool.on{background:#e3f3ec;border-color:#9ccfb9;color:#1d6a4c}.tool.off{background:#f3efe8;color:var(--muted)}.cov{margin:10px 0 0;padding-left:20px;font-size:13px}.gaps{color:#8a5a00}.evlist{max-height:340px;overflow:auto;background:#f5f2ec;border-radius:6px;padding:8px;margin-top:6px}.evline{font:12px/1.5 ui-monospace,Consolas,monospace;border-bottom:1px solid #e7e1d6;padding:3px 0;word-break:break-word}
.error{background:#fff0f1;border:1px solid #e5aab2;color:#8e1e31;padding:14px;border-radius:9px;margin-top:20px;white-space:pre-wrap}.warn{background:#fff7e6;border:1px solid #e8cf91;color:#7a5200;padding:12px;border-radius:9px;margin:12px 0;font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden;font-size:13px}th,td{text-align:left;padding:9px 11px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);background:#faf8f3}td a{color:var(--teal);font-weight:700}
.pill{display:inline-block;border-radius:999px;padding:2px 9px;font-size:11px;font-weight:800;background:#edf1ef}.pill.malicious,.pill.detected{background:#f9dde1;color:var(--red)}.pill.high_risk,.pill.false_positive,.pill.missed{background:#fde6d8;color:var(--orange)}.pill.suspicious,.pill.partial,.pill.interrupted{background:#fbf0d2;color:#80600f}.pill.no_findings,.pill.low_risk,.pill.clean,.pill.complete{background:#dff1e9;color:#1d6a4c}.pill.failed,.pill.cancelled{background:#eee;color:#555}.pill.running,.pill.queued,.pill.expanding{background:#dce9f6;color:#1d4f80}
.timeline{margin:10px 0;padding:0;list-style:none;font-size:13px}.timeline li{padding:3px 0 3px 18px;position:relative}.timeline li:before{content:"";position:absolute;left:3px;top:11px;width:8px;height:8px;border-radius:50%;background:var(--teal)}.timeline li.last:before{background:var(--orange)}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}
@media(max-width:900px){.overview{grid-template-columns:repeat(2,1fr)}.hero{grid-column:span 2}.grid{grid-template-columns:1fr}.mast{align-items:start;flex-direction:column}}
"""

_COMMON_JS = """
const $=s=>document.querySelector(s);
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
async function api(path,opts){const r=await fetch(path,opts);const t=await r.text();let j;try{j=JSON.parse(t)}catch(e){throw new Error("HTTP "+r.status+" instead of JSON: "+t.slice(0,200))}if(!r.ok)throw new Error(j.error||("HTTP "+r.status));return j}
const JSON_POST=(body)=>({method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{})});
function pill(v){return v?'<span class="pill '+esc(v)+'">'+esc(String(v).replace("_"," "))+'</span>':'<span class="muted">-</span>'}
function modeValue(){return document.querySelector("input[name=scan_mode]:checked").value}
async function health(){try{const h=await api("/api/health");const chip=(n,ok)=>'<span class="tool '+(ok?'on':'off')+'">'+n+': '+(ok?'ok':'missing')+'</span>';
 $("#health").innerHTML=chip("docker",h.tools.docker)+chip("kind",h.tools.kind)+chip("kubectl",h.tools.kubectl)+chip("cluster",h.cluster)+chip("sandbox image",h.images)+chip("Cisco scanner",h.cisco_configured)+chip("NVIDIA scanner",h.nvidia_configured)+'<span class="tool">monitoring: '+esc(h.monitoring_tier)+'</span>';
 $("#sandbox-note").innerHTML=h.sandbox_ready?"":'<div class="warn"><strong>Sandbox Scan is not ready on this machine:</strong> '+esc(h.sandbox_problem)+' Quick Scan still works. See docs/KALI-QUICKSTART.md.</div>'}catch(e){}}
"""

_NAV = (
    "<nav><a href='/' class='__A_scan__'>Scan</a><a href='/batch' class='__A_batch__'>Batch</a>"
    "<a href='/history' class='__A_history__'>History</a></nav>"
)


def _shell(title: str, active: str, body: str, script: str = "") -> str:
    nav = _NAV
    for name in ("scan", "batch", "history"):
        nav = nav.replace("__A_%s__" % name, "active" if name == active else "")
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>AgentGuard | " + title + "</title><style>" + _STYLE + "</style></head><body><main class='shell'>"
        "<header class='mast'><div><div class='eyebrow'>Static + dynamic security review</div><h1>AgentGuard</h1>"
        "<p class='muted'>Static evidence, decision-gate routing, and sandbox observations in one view.</p></div>"
        "<div class='trust'>Skill code runs only in isolated Kubernetes</div></header>" + nav + body
        + "</main><script>" + _COMMON_JS + script + "</script></body></html>"
    )


_MODE_RADIOS = (
    "<div class='modes' aria-label='Scan mode'>"
    "<label class='mode'><input type='radio' name='scan_mode' value=\"quick\" {quick_checked}>Quick Scan</label>"
    "<label class='mode'><input type='radio' name='scan_mode' value=\"sandbox\" {sandbox_checked}>Sandbox Scan</label>"
    "<label class='mode'><input type='radio' name='scan_mode' value=\"deep\" {deep_checked}>Deep Trace</label></div>"
)

_SCAN_BODY = (
    "<form class='scan' id='scan-form' onsubmit='return false'>"
    "<input type='text' id='source' name='source' placeholder='Public GitHub, GitLab, or Bitbucket URL (a /tree/branch/path link scans one skill)' value='{source}' required>"
    "<select id='sample' title='Sample library'><option value=''>Sample library...</option></select>"
    + _MODE_RADIOS +
    "<button id='submit-scan' type='submit'>Run scan</button></form>"
    "<p id='job-status' class='muted'>Quick Scan checks static evidence. Sandbox and Deep Trace execute inside Kubernetes."
    " Sandbox Scan runs static analysis first, then the skill inside an isolated pod with honeypot credentials.</p>"
    "<div id='sandbox-note'></div><div class='chips' id='health'></div>"
    "<div class='panel' id='progress-panel' style='display:none'><div class='row'><strong id='job-title'></strong>"
    "<span id='job-pill'></span><button class='danger' id='cancel' style='display:none'>Cancel</button>"
    "<span id='downloads'></span></div><ul class='timeline' id='timeline'></ul></div>"
    "<div id='results'></div>{content}"
)

_SCAN_SCRIPT = """
let timer=null,currentJob=null,started=0;
async function loadSamples(){try{const list=await api("/api/samples");const groups={};list.forEach(s=>{(groups[s.group]=groups[s.group]||[]).push(s)});
 let out='<option value="">Sample library...</option>';for(const g in groups){out+='<optgroup label="'+esc(g)+'">';groups[g].forEach(s=>{out+='<option value="sample:'+esc(s.id)+'">'+esc(s.label)+' ['+esc(s.expected)+'] - '+esc(s.shows)+'</option>'});out+='</optgroup>'}
 $("#sample").innerHTML=out}catch(e){}}
$("#sample").addEventListener("change",e=>{if(e.target.value){$("#source").value=e.target.value}});
function renderJob(j){$("#progress-panel").style.display="block";$("#job-title").textContent=j.label+" - "+j.scan_mode;$("#job-pill").innerHTML=pill(j.status);
 const lines=(j.progress||[]).map((p,i,a)=>'<li class="'+(i==a.length-1&&(j.status=="running")?"last":"")+'"><strong>'+esc(p.stage)+'</strong> '+esc(p.message)+' <span class="muted">+'+Math.max(0,Math.round(p.time-(a[0].time)))+'s</span></li>');
 if(j.status=="queued"){lines.push("<li><strong>queued</strong> waiting for the sandbox (one sandbox pod runs at a time)</li>")}
 $("#timeline").innerHTML=lines.join("");$("#cancel").style.display=(j.status=="queued"||j.status=="running")?"inline-block":"none"}
function done(j){clearInterval(timer);$("#submit-scan").disabled=false;
 $("#downloads").innerHTML=j.report?'<a class="btn ghost" href="/report/'+j.id+'/download.json">JSON</a> <a class="btn ghost" href="/report/'+j.id+'/download.html">HTML</a>':"";
 if(j.report){fetch("/report/"+j.id+"?fragment=1").then(r=>r.text()).then(t=>{$("#results").innerHTML=(j.status=="partial"&&j.error?'<div class="error"><strong>Scan finished with a gap:</strong> '+esc(j.error)+'</div>':"")+t})}
 else{$("#results").innerHTML='<div class="error">'+esc(j.status)+": "+esc(j.error||"no report was produced")+"</div>"}}
async function attach(id){currentJob=id;location.hash="job="+id;clearInterval(timer);$("#results").innerHTML="";$("#submit-scan").disabled=true;
 const tick=async()=>{try{const j=await api("/api/jobs/"+id);renderJob(j);$("#job-status").textContent="Scan "+j.status;
   if(["complete","partial","failed","cancelled","interrupted"].includes(j.status)){done(j)}}catch(e){clearInterval(timer);$("#job-status").textContent=e.message;$("#submit-scan").disabled=false}};
 await tick();timer=setInterval(tick,1500)}
$("#scan-form").addEventListener("submit",async()=>{
  const source=$("#source").value.trim();const scanMode=modeValue();const status=$("#job-status");
  $("#submit-scan").disabled=true;status.textContent="Queueing scan...";
  try{const response=await fetch("/api/jobs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({source, scan_mode:scanMode})});
    const text=await response.text();let job;try{job=JSON.parse(text)}catch(e){throw new Error("Queue request returned HTTP "+response.status+" instead of JSON: "+text.slice(0,300))}
    if(!response.ok){throw new Error(job.error||"Could not queue scan.")}
    attach(job.job_id)}catch(error){status.textContent=error.message||"Could not queue scan.";$("#submit-scan").disabled=false}});
$("#cancel").addEventListener("click",async()=>{if(currentJob){await api("/api/jobs/"+currentJob+"/cancel",JSON_POST())}});
loadSamples();health();const m=location.hash.match(/job=([0-9a-f]{32})/);if(m){attach(m[1])}
"""

_BATCH_BODY = (
    "<div class='panel' style='margin-top:22px'><h3>Batch scan</h3>"
    "<p class='muted'>One entry per line: a public repository URL (expanded into every skill it contains), a <code>/tree/branch/path</code> URL (one skill), or <code>sample:ID</code> from the library. Lines starting with # are ignored.</p>"
    "<textarea id='inputs' rows='9' placeholder='https://github.com/trailofbits/overtly-malicious-skills&#10;sample:runtime-exfil-evasive'></textarea>"
    "<div class='row'><button class='ghost' id='fill-mal' type='button'>Add all malicious samples</button>"
    "<button class='ghost' id='fill-ben' type='button'>Add all benign controls</button>"
    "<button class='ghost' id='fill-local' type='button'>Add local fixtures</button>"
    "<button class='ghost' id='fill-runtime' type='button'>Add public runtime samples</button>"
    "<label class='muted'><input type='checkbox' id='expand' checked> Expand repositories into individual skills</label></div>"
    + _MODE_RADIOS +
    "<div class='row'><button id='run-batch' type='button'>Run batch</button><span id='batch-status' class='muted'></span></div>"
    "<p class='muted'>Sandbox batches run one pod at a time, so they take a few minutes per skill.</p></div>"
    "<div id='sandbox-note'></div><div class='chips' id='health'></div><div id='batch-result'></div>"
)

_BATCH_SCRIPT = """
let samples=[],timer=null,batchId=null;
function add(list){const box=$("#inputs");const have=new Set(box.value.split("\\n").map(s=>s.trim()));list.forEach(s=>{const line="sample:"+s.id;if(!have.has(line)){box.value+=(box.value&&!box.value.endsWith("\\n")?"\\n":"")+line+"\\n"}})}
api("/api/samples").then(l=>{samples=l});
$("#fill-mal").onclick=()=>add(samples.filter(s=>s.expected=="malicious"&&!s.runtime));
$("#fill-runtime").onclick=()=>add(samples.filter(s=>s.runtime));
$("#fill-ben").onclick=()=>add(samples.filter(s=>s.expected=="benign"));
$("#fill-local").onclick=()=>add(samples.filter(s=>s.kind=="local"));
function table(b){const rows=b.jobs.map(j=>'<tr><td>'+(j.status=="complete"||j.status=="partial"?'<a href="/report/'+j.id+'">'+esc(j.label)+'</a>':esc(j.label))+'<br><span class="meta">'+esc(j.source)+'</span></td><td>'+esc(j.scan_mode)+'</td><td>'+pill(j.status)+'</td><td>'+pill(j.verdict)+'</td><td>'+esc(j.severity||"-")+'</td><td>'+esc(j.finding_count==null?"-":j.finding_count)+'</td><td>'+esc(j.expected||"-")+' '+pill(j.outcome)+'</td><td class="meta">'+esc(j.error||"")+'</td></tr>').join("");
 const counts=Object.entries(b.counts).map(([k,v])=>pill(k)+" "+v).join(" &nbsp; ");const out=Object.entries(b.outcomes).map(([k,v])=>pill(k)+" "+v).join(" &nbsp; ");
 return '<div class="row"><strong>Batch '+esc(b.status)+'</strong> '+counts+(out?' &nbsp;|&nbsp; '+out:'')+(b.status=="running"?' <button class="danger" id="cancel-batch">Cancel batch</button>':'')+' <a class="btn ghost" href="/api/batches/'+b.id+'/summary.csv">CSV</a></div>'+(b.errors.length?'<div class="warn">'+b.errors.map(esc).join("<br>")+'</div>':'')+'<table><tr><th>Skill</th><th>Mode</th><th>Status</th><th>Verdict</th><th>Severity</th><th>Findings</th><th>Expected / outcome</th><th>Note</th></tr>'+rows+'</table>'}
async function poll(){try{const b=await api("/api/batches/"+batchId);$("#batch-result").innerHTML=table(b);const c=$("#cancel-batch");if(c){c.onclick=()=>api("/api/batches/"+batchId+"/cancel",JSON_POST())}
 if(b.status!="running"&&b.status!="expanding"){clearInterval(timer);$("#run-batch").disabled=false}}catch(e){clearInterval(timer);$("#batch-status").textContent=e.message;$("#run-batch").disabled=false}}
function attach(id){batchId=id;location.hash="batch="+id;clearInterval(timer);poll();timer=setInterval(poll,2500)}
$("#run-batch").onclick=async()=>{const inputs=$("#inputs").value.split("\\n");$("#run-batch").disabled=true;$("#batch-status").textContent="Queueing...";
 try{const b=await api("/api/batches",JSON_POST({inputs:inputs,scan_mode:modeValue(),expand:$("#expand").checked}));$("#batch-status").textContent="";attach(b.batch_id)}catch(e){$("#batch-status").textContent=e.message;$("#run-batch").disabled=false}};
health();const m=location.hash.match(/batch=([0-9a-f]{32})/);if(m){attach(m[1])}
"""

_HISTORY_BODY = (
    "<div class='panel' style='margin-top:22px'><h3>Scan history</h3>"
    "<p class='muted'>Stored on disk, so it survives dashboard restarts. Reports are downloadable as JSON or standalone HTML.</p>"
    "<div id='history'></div></div><div class='panel' style='margin-top:18px'><h3>Batches</h3><div id='batches'></div></div>"
)

_HISTORY_SCRIPT = """
async function load(){const jobs=await api("/api/jobs");
 $("#history").innerHTML=jobs.length?'<table><tr><th>When (UTC)</th><th>Skill</th><th>Mode</th><th>Status</th><th>Verdict</th><th>Severity</th><th>Findings</th><th></th></tr>'+jobs.map(j=>'<tr><td>'+esc((j.created_at||"").replace("T"," ").replace("+00:00",""))+'</td><td>'+esc(j.label)+'<br><span class="meta">'+esc(j.source)+'</span></td><td>'+esc(j.scan_mode)+'</td><td>'+pill(j.status)+'</td><td>'+pill(j.verdict)+'</td><td>'+esc(j.severity||"-")+'</td><td>'+esc(j.finding_count==null?"-":j.finding_count)+'</td><td>'+(j.report?'<a href="/report/'+j.id+'">view</a> &middot; <a href="/report/'+j.id+'/download.json">json</a> &middot; <a href="/report/'+j.id+'/download.html">html</a> &middot; ':'')+(["complete","partial","failed","cancelled","interrupted"].includes(j.status)?'<a href="#" data-del="'+j.id+'">delete</a>':'<a href="/#job='+j.id+'">watch</a>')+'</td></tr>').join("")+'</table>':'<p class="muted">No scans yet.</p>';
 document.querySelectorAll("[data-del]").forEach(a=>a.onclick=async e=>{e.preventDefault();await api("/api/jobs/"+a.dataset.del,{method:"DELETE"});load()});
 const bs=await api("/api/batches");$("#batches").innerHTML=bs.length?'<table><tr><th>When (UTC)</th><th>Mode</th><th>Status</th><th>Skills</th><th>Outcomes</th><th></th></tr>'+bs.map(b=>'<tr><td>'+esc((b.created_at||"").replace("T"," ").replace("+00:00",""))+'</td><td>'+esc(b.scan_mode)+'</td><td>'+pill(b.status)+'</td><td>'+b.total+'</td><td>'+Object.entries(b.outcomes).map(([k,v])=>pill(k)+" "+v).join(" ")+'</td><td><a href="/batch#batch='+b.id+'">open</a></td></tr>').join("")+'</table>':'<p class="muted">No batches yet.</p>'}
load().catch(e=>{$("#history").innerHTML='<div class="error">'+esc(e.message)+'</div>'});
"""

_PAGE = _shell("Static + Dynamic Review", "scan", _SCAN_BODY, _SCAN_SCRIPT)
_BATCH_PAGE = _shell("Batch scan", "batch", _BATCH_BODY, _BATCH_SCRIPT)
_HISTORY_PAGE = _shell("History", "history", _HISTORY_BODY, _HISTORY_SCRIPT)


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _page(template: str, *, source: str = "", content: str = "", scan_mode: str = "quick") -> str:
    return (template
            .replace("{source}", _esc(source))
            .replace("{content}", content)
            .replace("{quick_checked}", "checked" if scan_mode == "quick" else "")
            .replace("{sandbox_checked}", "checked" if scan_mode == "sandbox" else "")
            .replace("{deep_checked}", "checked" if scan_mode == "deep" else ""))


def _render(result: dict) -> str:
    return render_report(result)


# ----------------------------------------------------------------------------- readiness
_HEALTH_CACHE: dict = {"time": 0.0, "value": None}


def readiness() -> dict:
    """Can a Sandbox Scan run here? Cached for 15 seconds because it shells out to kubectl/docker."""
    now = time.time()
    cached = _HEALTH_CACHE["value"]
    if cached is not None and now - _HEALTH_CACHE["time"] < 15:
        return cached
    tools = {name: shutil.which(name) is not None for name in ("docker", "kind", "kubectl")}
    cluster = False
    if tools["kubectl"]:
        try:
            done = subprocess.run(["kubectl", "get", "nodes", "-o", "name"], capture_output=True, text=True,
                                  timeout=6, check=False)
            cluster = done.returncode == 0 and bool(done.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            cluster = False
    images = False
    if tools["docker"]:
        try:
            from .dynamic.runner import image_tag

            done = subprocess.run(["docker", "image", "inspect", "agentguard-sandbox:" + image_tag()],
                                  capture_output=True, timeout=8, check=False)
            images = done.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            images = False
    problems = []
    missing = [name for name, present in tools.items() if not present]
    if missing:
        problems.append("missing command(s): " + ", ".join(missing) + ".")
    elif not cluster:
        problems.append("kubectl cannot reach a cluster (run: kind create cluster --name agentguard).")
    elif not images:
        problems.append("sandbox images are not built yet (run: python -m agentguard.cli prepare-sandbox).")
    scanner_info = scanners.status()
    value = {
        "tools": tools, "cluster": cluster, "images": images,
        "sandbox_ready": not problems, "sandbox_problem": " ".join(problems),
        "cisco_configured": scanner_info["cisco"]["available"],
        "nvidia_configured": scanner_info["nvidia"]["available"],
        "scanners": scanner_info,
        "agent_mode": os.environ.get("AGENTGUARD_AGENT_MODE", "").strip().lower() == "ollama",
        "monitoring_tier": os.environ.get("AGENTGUARD_MONITORING_TIER", "fallback"),
    }
    _HEALTH_CACHE.update(time=now, value=value)
    return value


def _resolve_source(raw: str) -> tuple[str, str | None]:
    """Return ``(source, sample_id)``; local paths are only reachable through the sample library."""
    value = (raw or "").strip()
    if value.startswith("sample:"):
        sample_id = value.split(":", 1)[1].strip()
        try:
            return sample_library.resolve_source(sample_id), sample_id
        except KeyError as exc:
            raise ValueError("Unknown sample: %s" % sample_id) from exc
    return validate_public_git_url(value), None


def _summary_csv(batch: dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["label", "source", "mode", "status", "verdict", "severity", "findings", "expected", "outcome", "error"])
    for job in batch.get("jobs", []):
        writer.writerow([job.get("label"), job.get("source"), job.get("scan_mode"), job.get("status"),
                         job.get("verdict"), job.get("severity"), job.get("finding_count"), job.get("expected"),
                         job.get("outcome"), job.get("error")])
    return buffer.getvalue()


def _report_fragment(meta: dict, result: dict) -> str:
    header = (
        "<div class='row' style='margin-top:18px'><strong>%s</strong><span class='meta'>%s</span> %s "
        "<span class='muted'>%s mode</span></div>"
    ) % (_esc(meta.get("label")), _esc(meta.get("source")),
         "<span class='pill %s'>%s</span>" % (_esc(meta.get("status")), _esc(meta.get("status"))),
         _esc(meta.get("scan_mode")))
    return header + render_report(result)


class Handler(BaseHTTPRequestHandler):
    store: JobStore
    server_version = "AgentGuard"

    # -- plumbing
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        _LOGGER.info("%s - %s", self.address_string(), format % args)

    def _send(self, body: str | bytes, status: int = 200, content_type: str = "text/html; charset=utf-8",
              headers: dict | None = None) -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, payload: object, status: int = 200) -> None:
        self._send(json.dumps(payload), status, "application/json")

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"error": message}, status)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length") from None
        if length > MAX_BODY:
            raise ValueError("Request body too large")
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            raise ValueError("Content-Type must be application/json")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            value = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Request body is not valid JSON") from None
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object")
        return value

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            self._route(method, parts, query)
        except KeyError:
            self._error("Not found", 404)
        except ValueError as exc:
            self._error(str(exc), 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # report, never hide
            _LOGGER.exception("Request failed: %s %s", method, self.path)
            self._error("Internal error: %s" % exc, 500)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    # -- routes
    def _route(self, method: str, parts: list[str], query: dict) -> None:
        store = self.store
        if method == "GET":
            if parts == []:
                return self._send(_page(_PAGE))
            if parts == ["batch"]:
                return self._send(_page(_BATCH_PAGE))
            if parts == ["history"]:
                return self._send(_HISTORY_PAGE)
            if parts[:1] == ["report"] and len(parts) >= 2:
                return self._report(parts, query)
            if parts == ["api", "health"]:
                return self._json(readiness())
            if parts == ["api", "samples"]:
                return self._json(sample_library.public_listing())
            if parts == ["api", "jobs"]:
                return self._json(store.list_jobs())
            if len(parts) == 3 and parts[:2] == ["api", "jobs"]:
                return self._json(store.get(parts[2]))
            if parts == ["api", "batches"]:
                return self._json(store.list_batches())
            if len(parts) == 3 and parts[:2] == ["api", "batches"]:
                return self._json(store.get_batch(parts[2]))
            if len(parts) == 4 and parts[:2] == ["api", "batches"] and parts[3] == "summary.csv":
                batch = store.get_batch(parts[2])
                return self._send(_summary_csv(batch), 200, "text/csv; charset=utf-8",
                                  {"Content-Disposition": "attachment; filename=batch-%s.csv" % parts[2][:8]})
            raise KeyError("route")
        if method == "POST":
            if parts == ["api", "jobs"]:
                body = self._body()
                scan_mode = str(body.get("scan_mode") or "quick")
                source, sample_id = _resolve_source(str(body.get("source") or ""))
                job_id = store.submit(source, scan_mode, sample_id=sample_id)
                return self._json({"job_id": job_id, "status": "queued"}, 202)
            if len(parts) == 4 and parts[:2] == ["api", "jobs"] and parts[3] == "cancel":
                self._body()
                return self._json(store.cancel(parts[2]))
            if parts == ["api", "batches"]:
                body = self._body()
                inputs = body.get("inputs")
                if isinstance(inputs, str):
                    inputs = inputs.splitlines()
                if not isinstance(inputs, list):
                    raise ValueError("inputs must be a list of URLs or sample: ids")
                batch_id = store.submit_batch([str(item) for item in inputs[:500]],
                                              str(body.get("scan_mode") or "quick"),
                                              expand=bool(body.get("expand", True)))
                return self._json({"batch_id": batch_id}, 202)
            if len(parts) == 4 and parts[:2] == ["api", "batches"] and parts[3] == "cancel":
                self._body()
                return self._json(store.cancel_batch(parts[2]))
            raise KeyError("route")
        if method == "DELETE" and len(parts) == 3 and parts[:2] == ["api", "jobs"]:
            store.delete(parts[2])
            return self._json({"deleted": parts[2]})
        raise KeyError("route")

    def _report(self, parts: list[str], query: dict) -> None:
        job_id = parts[1]
        if not ID_PATTERN.match(job_id):
            raise KeyError(job_id)
        meta = self.store.get(job_id)
        if len(parts) == 3 and parts[2] == "download.json":
            path = self.store.report_file(job_id)
            if path is None:
                raise KeyError(job_id)
            return self._send(path.read_bytes(), 200, "application/json",
                              {"Content-Disposition": "attachment; filename=agentguard-%s.json" % job_id[:8]})
        result = self.store.result(job_id)
        if result is None:
            message = "<div class='error'>Scan %s: %s</div>" % (_esc(meta.get("status")), _esc(meta.get("error") or "no report yet"))
            return self._send(message if query.get("fragment") else _shell("Report", "history", message))
        fragment = _report_fragment(meta, result)
        if len(parts) == 3 and parts[2] == "download.html":
            document = _shell("Report " + job_id[:8], "history", fragment).replace(
                "<nav>", "<nav style='display:none'>", 1)
            document = re.sub(r"<script>.*?</script>", "", document, flags=re.S)
            return self._send(document, 200, headers={
                "Content-Disposition": "attachment; filename=agentguard-%s.html" % job_id[:8]})
        if len(parts) != 2:
            raise KeyError(job_id)
        if query.get("fragment"):
            return self._send(fragment)
        return self._send(_shell("Report " + job_id[:8], "history", fragment))


def make_server(host: str, port: int, store: JobStore) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"store": store})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve(host: str = "127.0.0.1", port: int = 8080, data_dir: Path | None = None) -> None:
    root = Path(data_dir or os.environ.get("AGENTGUARD_DATA_DIR") or REPO_ROOT / "runs" / "web")
    store = JobStore(root)
    server = make_server(host, port, store)

    def _stop(signum, frame):  # noqa: ARG001
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    print("AgentGuard dashboard: http://%s:%d  (data: %s)" % (host, port, root), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        store.stop_all()
        server.server_close()
