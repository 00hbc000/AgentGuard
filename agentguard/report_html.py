"""HTML rendering of a scan report (used by the dashboard and the downloadable report).

Written without nested same-quote f-strings so it parses on Python 3.11 as well as 3.12+.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from typing import Any

from .dynamic.collector import CATEGORY_LABELS, event_category

SEVERITIES = ("critical", "high", "medium", "low", "info")
_VERDICT_CLASS = {"malicious": "critical", "high_risk": "high", "suspicious": "medium",
                  "inconclusive": "info", "no_findings": "low", "low_risk": "low"}
_MONITOR_LABELS = {"sink": "Controlled sink", "guard": "Python runtime guard", "strace": "strace syscall trace",
                   "tetragon": "Tetragon (eBPF)", "agent": "LLM agent"}
_COVERAGE_LABELS = {"commands_run": "Commands run", "entrypoint_found": "Entrypoint found",
                    "no_entrypoint": "No runnable entrypoint", "trace_available": "strace available",
                    "guard_enabled": "Runtime guard enabled"}


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _truncate(value: object, limit: int = 300) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."


def _finding_card(item: dict[str, Any]) -> str:
    severity = str(item.get("severity", "INFO")).lower()
    path = item.get("file_path") or "package"
    if item.get("line_number"):
        path = "%s:%s" % (path, item["line_number"])
    details = ""
    if item.get("evidence"):
        details += "<details><summary>Evidence</summary><div class='code'>%s</div></details>" % esc(item["evidence"])
    raw = item.get("raw") or {}
    if raw:
        details += "<details><summary>Raw %s finding</summary><div class='code'>%s</div></details>" % (
            esc(item.get("tool")), esc(json.dumps(raw, indent=2)))
    confidence = item.get("confidence")
    return (
        "<article class='finding %s'><div class='finding-head'><span class='badge'>%s &middot; %s &middot; %s</span>"
        "<span class='meta'>%s</span></div><h4>%s</h4><p>%s</p>"
        "<p class='meta'>Confidence: %s &middot; Fingerprint: <span class='fingerprint'>%s</span></p>"
        "<p><strong>Remediation:</strong> %s</p>%s</article>"
    ) % (esc(severity), esc(severity.upper()), esc(item.get("tool")), esc(item.get("rule_id")), esc(path),
         esc(item.get("message") or "Finding"), esc(item.get("description")),
         esc(confidence if confidence is not None else "not provided"), esc(item.get("fingerprint")),
         esc(item.get("remediation")), details)


def _event_summary(event: dict[str, Any]) -> str:
    keys = ("host", "destination", "path", "url", "method", "bytes", "command", "cwd", "exit_code", "api", "args",
            "address", "port", "external", "source", "reason", "timed_out", "stdout", "stderr", "error")
    parts = []
    for key in keys:
        if event.get(key) not in (None, "", [], False):
            parts.append("%s=%s" % (key, _truncate(event[key], 160)))
    hits = event.get("canary_hits") or event.get("canary_in_output") or []
    if hits:
        parts.append("canaries=" + ", ".join(sorted({str(hit.get("name")) for hit in hits if isinstance(hit, dict)})))
    return "  ".join(parts)


def _evidence_panel(dynamic: dict[str, Any]) -> str:
    events = dynamic.get("events") or []
    groups: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        groups.setdefault(event_category(event), []).append(event)
    counts = dynamic.get("evidence_counts") or {key: len(value) for key, value in groups.items()}
    monitors = dynamic.get("monitors") or {}
    coverage = dynamic.get("coverage") or {}
    monitor_html = "".join(
        "<span class='tool %s'>%s: %s</span>" % ("on" if enabled else "off", esc(_MONITOR_LABELS.get(name, name)),
                                                  "active" if enabled else "no evidence")
        for name, enabled in monitors.items())
    coverage_html = "".join(
        "<li>%s: <strong>%s</strong></li>" % (esc(_COVERAGE_LABELS.get(name, name)), esc(value))
        for name, value in coverage.items())
    count_html = "".join(
        "<span class='tool'>%s: %s</span>" % (esc(CATEGORY_LABELS.get(name, name)), esc(count))
        for name, count in counts.items()) or "<span class='muted'>No runtime events were recorded.</span>"
    group_html = ""
    for category in CATEGORY_LABELS:
        items = groups.get(category)
        if not items:
            continue
        lines = "".join(
            "<div class='evline'><strong>%s</strong> %s</div>" % (esc(item.get("type")), esc(_event_summary(item)))
            for item in items[:200])
        group_html += "<details%s><summary>%s (%d)</summary><div class='evlist'>%s</div></details>" % (
            " open" if category in {"sink", "honeypot"} else "", esc(CATEGORY_LABELS[category]), len(items), lines)
    raw = "<details><summary>All runtime events (raw JSON)</summary><div class='code'>%s</div></details>" % esc(
        json.dumps(events, indent=2))
    return (
        "<section class='panel'><h3>Runtime evidence</h3>"
        "<p><strong>Status:</strong> %s &middot; <strong>Monitoring tier:</strong> %s &middot; "
        "<strong>Runtime findings:</strong> %s</p><p class='muted'>%s</p>"
        "<div class='toollist'>%s</div><ul class='cov'>%s</ul>"
        "<div class='label' style='margin-top:12px'>Evidence by source</div><div class='toollist'>%s</div>%s%s</section>"
    ) % (esc(dynamic.get("status")), esc(dynamic.get("monitoring_tier")), esc(dynamic.get("finding_count")),
         esc(dynamic.get("error") or "No dynamic error"), monitor_html, coverage_html, count_html, group_html, raw)


def _remediation_panel(findings: list[dict[str, Any]]) -> str:
    seen: dict[str, list[str]] = {}
    for item in findings:
        text = item.get("remediation")
        if text:
            seen.setdefault(str(text), []).append(str(item.get("rule_id")))
    if not seen:
        return ""
    rows = "".join("<li>%s <span class='meta'>(%s)</span></li>" % (esc(text), esc(", ".join(sorted(set(rules)))))
                   for text, rules in seen.items())
    return "<section class='panel' style='margin-top:18px'><h3>Remediation</h3><ul class='cov'>%s</ul></section>" % rows


def render_report(result: dict[str, Any]) -> str:
    findings = result.get("findings", [])
    severity_counts = Counter(str(item.get("severity", "INFO")).lower() for item in findings)
    tool_counts = Counter(str(item.get("tool", "unknown")) for item in findings)
    max_severity = result.get("aggregate_severity", "INFO")
    status = result.get("scan_status", "unknown")
    tools = result.get("tools_used", [])
    gate = result.get("decision_gate")
    dynamic = result.get("dynamic")
    stages = result.get("stages", {})
    mode = stages.get("mode", {}).get("status", "quick")
    verdict = result.get("verdict") or {}
    label = verdict.get("label")
    runtime = [item for item in findings if item.get("tool") == "agentguard_sandbox"]
    static = [item for item in findings if item.get("tool") != "agentguard_sandbox"]

    if verdict:
        gaps = "".join("<li>%s</li>" % esc(gap) for gap in verdict.get("gaps", []))
        hero = (
            "<div class='hero verdict %s'><div class='label'>Verdict &middot; %s</div><h2>%s</h2>"
            "<p>%s</p><p class='muted'>%s</p>%s</div>"
        ) % (_VERDICT_CLASS.get(label, "info"), esc(mode), esc(verdict.get("headline")), esc(verdict.get("reason")),
             esc(verdict.get("recommendation")),
             ("<ul class='cov gaps'>%s</ul>" % gaps) if gaps else "")
    else:
        hero = ("<div class='hero'><div class='label'>Verdict &middot; %s</div><h2>%s</h2>"
                "<p class='muted'>%d normalized findings &middot; %s</p></div>") % (
                    esc(mode), esc(max_severity), len(findings), esc(status))

    stat = "<div class='stat'><span class='label'>%s</span><span class='value'>%s</span></div>"
    overview = "<section class='overview'>%s%s%s%s%s</section>" % (
        hero, stat % ("Critical", severity_counts.get("critical", 0)), stat % ("High", severity_counts.get("high", 0)),
        stat % ("Medium", severity_counts.get("medium", 0)), stat % ("Tools", len(tools)))

    stage_items = []
    for name, details in stages.items():
        if not isinstance(details, dict):
            continue
        reason = details.get("reason") or details.get("note")
        stage_items.append("<div class='tool'><strong>%s</strong>: %s%s</div>" % (
            esc(name), esc(details.get("status", "unknown")), (" &middot; " + esc(reason)) if reason else ""))
    stage_html = "".join(stage_items) or "<span class='muted'>No stage data</span>"
    stages_panel = "<section class='panel' style='margin-top:18px'><h3>Pipeline stages</h3><div class='toollist'>%s</div></section>" % stage_html

    def findings_block(title: str, items: list[dict[str, Any]], empty: str) -> str:
        cards = "".join(_finding_card(item) for item in items) or "<p class='muted'>%s</p>" % esc(empty)
        return "<section class='panel' style='margin-bottom:18px'><h3>%s (%d)</h3><div class='findings'>%s</div></section>" % (
            esc(title), len(items), cards)

    findings_html = findings_block("Static findings", static, "No static findings.")
    if dynamic is not None or runtime:
        findings_html += findings_block("Runtime findings", runtime,
                                        "No runtime findings. See coverage in the runtime evidence panel.")

    max_count = max(severity_counts.values(), default=1)
    bars = "".join(
        "<div class='barrow'><span>%s</span><div class='track'><div class='fill %s' style='width:%d%%'></div></div>"
        "<strong>%d</strong></div>" % (level.upper(), level, round(severity_counts.get(level, 0) / max_count * 100),
                                      severity_counts.get(level, 0))
        for level in SEVERITIES)

    gate_panel = ""
    if gate:
        gate_panel = ("<section class='panel'><h3>Decision gate</h3><p><strong>%s</strong>%s</p>"
                      "<p class='muted'>%s</p></section>") % (
                          "Escalate" if gate.get("escalate") else "Stop", " (forced by scan mode)" if gate.get("forced") else "",
                          esc(gate.get("reason")))
    dynamic_panel = _evidence_panel(dynamic) if dynamic else ""

    tool_list = "".join("<span class='tool'>%s</span>" % esc(tool) for tool in tools) or "<span class='muted'>No scanner completed</span>"
    ingestion = (stages.get("ingestion") or {}).get("details") or {}
    source_lines = "".join(
        "%s: %s<br>" % (esc(key), esc(ingestion[key]))
        for key in ("kind", "url", "branch", "subpath", "commit_sha", "files", "symlinks_removed") if ingestion.get(key) not in (None, ""))
    coverage = (
        "<section class='panel' style='margin-top:18px'><h3>Scanner coverage</h3><div class='toollist'>%s</div>"
        "<p class='muted'>%s</p><p class='meta'>%sScan ID: %s</p></section>"
    ) % (tool_list, esc(", ".join("%s: %s" % item for item in tool_counts.items())), source_lines, esc(result.get("scan_id")))

    return (
        overview + stages_panel
        + "<div class='grid'><div>" + findings_html + "</div><aside>" + gate_panel + dynamic_panel
        + _remediation_panel(findings)
        + "<section class='panel' style='margin-top:18px'><h3>Severity profile</h3><div class='bars'>%s</div></section>" % bars
        + coverage + "</aside></div>"
    )
