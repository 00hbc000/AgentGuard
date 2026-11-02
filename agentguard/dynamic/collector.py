"""Normalize runtime events into findings.

Evidence sources are kept separate and labelled (see :func:`event_category`):

* ``sink``            - requests that reached the controlled sink (outside the pod; authoritative)
* ``honeypot``        - decoy files opened (python audit hook / strace)
* ``network``         - DNS lookups, connection attempts, HTTP payloads (python audit hook / strace)
* ``execution``       - commands the harness ran, their exit codes and output
* ``agent``           - Ollama agent actions
* ``tetragon``        - kernel-level events from Tetragon when available
* ``error``           - harness errors, timeouts, missing entrypoints

Only **canary proof** produces CRITICAL: a honeypot secret that embeds this scan's token
was observed in sink traffic. Attempts, reads and printed secrets are reported at lower
severities so the report never over-claims.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..models import Finding, Location

_CATEGORIES = {
    "network_sink": "sink",
    "honeypot_exfiltration": "sink",
    "honeypot_read": "honeypot",
    "sensitive_read": "honeypot",
    "network_attempt": "network",
    "dns_lookup": "network",
    "http_request": "network",
    "network_payload": "network",
    "process_spawn": "execution",
    "dynamic_exec": "execution",
    "execution_plan": "execution",
    "skill_command": "execution",
    "sandbox_image": "execution",
    "agent_action": "agent",
    "agent_limit": "agent",
    "agent_error": "error",
    "execution_error": "error",
    "prepare_error": "error",
    "no_entrypoint": "error",
    "tetragon": "tetragon",
    "tetragon_unavailable": "tetragon",
}
CATEGORY_LABELS = {
    "sink": "Sink events (left the pod)",
    "honeypot": "Honeypot access",
    "network": "Network activity",
    "execution": "Execution",
    "agent": "Agent actions",
    "tetragon": "Tetragon",
    "error": "Errors and gaps",
    "other": "Other",
}


def event_category(event: dict[str, Any]) -> str:
    return _CATEGORIES.get(str(event.get("type")), "other")


@dataclass
class DynamicResult:
    status: str
    monitoring_tier: str
    findings: list[Finding] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    coverage: dict[str, Any] = field(default_factory=dict)
    monitors: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for event in self.events:
            category = event_category(event)
            counts[category] = counts.get(category, 0) + 1
        return {
            "status": self.status,
            "monitoring_tier": self.monitoring_tier,
            "monitors": self.monitors,
            "coverage": self.coverage,
            "finding_count": len(self.findings),
            "findings": [item.to_dict() for item in self.findings],
            "events": self.events,
            "evidence_counts": counts,
            "error": self.error,
        }


# ------------------------------------------------------------------ helpers
def _make(rule_id: str, category: str, severity: str, message: str, description: str,
          evidence: dict[str, Any], *, finding_id: str, path: str | None = None,
          proven: bool = False, confidence: float = 0.9, raw: dict[str, Any] | None = None) -> Finding:
    return Finding(
        tool="agentguard_sandbox", tool_version="0.1.0", finding_id=finding_id, rule_id=rule_id,
        category=category, severity=severity, message=message, description=description,
        confidence=1.0 if proven else confidence,
        remediation="Do not install or run this skill." if severity in {"CRITICAL", "HIGH"}
        else "Review the runtime evidence and confirm the behaviour is intended.",
        location=Location(path=path, start_line=None),
        evidence={**evidence, "proven": proven}, raw_finding=raw or evidence,
    )


def _is_internal_host(host: str, allowed: set[str]) -> bool:
    host = host.lower().rstrip(".")
    if not host or host in allowed or host in {"localhost", "ip6-localhost"}:
        return True
    if host.endswith((".svc.cluster.local", ".cluster.local", ".svc")) or host.startswith("agentguard-sink"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _classify_destination(host: str, port: Any, allowed: set[str]) -> str | None:
    """Return 'external', 'cluster', or None when the destination is expected."""
    if _is_internal_host(host, allowed):
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "external"  # a public-looking hostname
    if ip.is_global:
        return "external"
    if port == 53:  # private resolver traffic is the sandbox's own DNS
        return None
    return "cluster"


def _destinations(events: list[dict[str, Any]], allowed: set[str]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for event in events:
        kind = event.get("type")
        host: str | None = None
        port: Any = None
        if kind == "dns_lookup":
            host, port = str(event.get("host") or ""), event.get("port")
        elif kind == "network_attempt":
            address = event.get("address")
            if isinstance(address, list) and address:
                host, port = str(address[0]), address[1] if len(address) > 1 else None
        elif kind == "http_request":
            from urllib.parse import urlparse
            parsed = urlparse(str(event.get("url") or ""))
            host, port = parsed.hostname or "", parsed.port
        elif kind == "network_payload":
            host = str(event.get("host") or "").split(":")[0] or None
        if not host:
            continue
        classification = _classify_destination(host, port, allowed)
        if classification is None:
            continue
        entry = found.setdefault(host, {"classification": classification, "ports": set(), "sources": set(), "types": set()})
        if port:
            entry["ports"].add(port)
        entry["sources"].add(str(event.get("source", "python_audit")))
        entry["types"].add(str(kind))
        if classification == "external":
            entry["classification"] = "external"
    return found


def _names(hits: Iterable[dict[str, Any]]) -> list[str]:
    return sorted({str(hit.get("name")) for hit in hits if isinstance(hit, dict)})


def derive_findings(events: list[dict[str, Any]], *, scan_token: str | None = None,
                    allowed_hosts: Iterable[str] = ()) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Return ``(findings, derived_events)`` computed from raw events."""
    allowed = {str(item).lower() for item in allowed_hosts}
    findings: list[Finding] = []
    derived: list[dict[str, Any]] = []

    def token_ok(hit: dict[str, Any]) -> bool:
        return scan_token is None or hit.get("token") == scan_token

    # 1. Legacy / pre-derived exfiltration events (kept for demo + backwards compatibility).
    for event in events:
        if event.get("type") == "honeypot_exfiltration" and event.get("honeypot_hit"):
            path = str(event.get("path") or "honeypot")
            findings.append(_make(
                "DYN_HONEYPOT_EXFIL", "honeypot_exfiltration", "CRITICAL",
                "Sandboxed skill accessed a honeypot credential and attempted external transmission",
                "A monitored honeypot file was read and data was sent to an external sink.",
                {"event": event}, finding_id=f"DYN_HONEYPOT_EXFIL:{path}", path=path, proven=True, raw=event))

    # 2. Sink-confirmed canary delivery -> CRITICAL, proven.
    sink_names: set[str] = set()
    for event in events:
        if event.get("type") != "network_sink":
            continue
        hits = [hit for hit in event.get("canary_hits") or [] if token_ok(hit)]
        if not hits:
            continue
        names = _names(hits)
        sink_names.update(names)
        destination = str(event.get("host") or event.get("path") or "sink")
        proof = {"type": "honeypot_exfiltration", "honeypot_hit": True, "proof": "canary_in_sink_traffic",
                 "destination": destination, "canary_names": names,
                 "encodings": sorted({str(h.get("encoding")) for h in hits}),
                 "bytes": event.get("bytes"), "method": event.get("method"), "path": event.get("path"),
                 "monitoring_source": "sink"}
        derived.append(proof)
        findings.append(_make(
            "DYN_HONEYPOT_EXFIL", "honeypot_exfiltration", "CRITICAL",
            "Honeypot secret was transmitted over the network (proven by canary in sink traffic)",
            f"The sink received {', '.join(names)} planted for this scan (destination header: {destination}).",
            {"canary_names": names, "encodings": proof["encodings"], "destination": destination,
             "sink_event": event}, finding_id=f"DYN_HONEYPOT_EXFIL:{destination}:{','.join(names)}",
            path=names[0] if names else None, proven=True, raw=event))

    # 3. In-pod network payload / HTTP request carrying a canary that the sink did not confirm.
    attempted: dict[str, dict[str, Any]] = {}
    for event in events:
        if event.get("type") in {"network_payload", "http_request"}:
            hits = [hit for hit in event.get("canary_hits") or [] if token_ok(hit)]
            names = set(_names(hits))
            if names and not names <= sink_names:
                destination = str(event.get("host") or event.get("url") or "unknown")
                attempted.setdefault(destination, {"names": set(), "event": event})["names"].update(names)
    for destination, info in attempted.items():
        names = sorted(info["names"])
        findings.append(_make(
            "DYN_EXFIL_ATTEMPT", "honeypot_exfiltration_attempt", "HIGH",
            f"Honeypot secret was written to a network request to {destination} (delivery not confirmed)",
            "The runtime guard saw a honeypot secret inside an outbound request. The sandbox NetworkPolicy "
            "blocks external hosts, so the sink did not observe delivery - this is an attempt, not proof of loss.",
            {"destination": destination, "canary_names": names, "event": info["event"]},
            finding_id=f"DYN_EXFIL_ATTEMPT:{destination}:{','.join(names)}", path=destination,
            raw=info["event"], confidence=0.95))

    # 4. Secrets printed to stdout/stderr or agent output.
    exposed: set[str] = set()
    commands: list[str] = []
    for event in events:
        if event.get("type") in {"skill_command", "agent_action"}:
            hits = [hit for hit in event.get("canary_in_output") or [] if token_ok(hit)]
            if hits:
                exposed.update(_names(hits))
                commands.append(" ".join(map(str, event.get("command") or [event.get("tool", "")])))
    if exposed:
        findings.append(_make(
            "DYN_ENV_EXPOSED", "secret_exposure", "HIGH",
            f"Skill printed {len(exposed)} honeypot secret(s) to its output (environment/credential dump)",
            "Honeypot environment variables or files were read and written to stdout/stderr, where the "
            "host agent would ingest them. This is the behaviour of an environment-harvesting skill.",
            {"canary_names": sorted(exposed), "commands": commands[:5]},
            finding_id=f"DYN_ENV_EXPOSED:{','.join(sorted(exposed))}", path=commands[0] if commands else None))

    # 5. Honeypot reads.
    reads = sorted({str(e.get("path")) for e in events if e.get("type") in {"honeypot_read", "sensitive_read"}})
    destinations = _destinations(events, allowed)
    external = {host: info for host, info in destinations.items() if info["classification"] == "external"}
    suspicious_context = bool(reads or exposed or sink_names or attempted)
    if reads:
        sources = sorted({str(e.get("source")) for e in events if e.get("type") in {"honeypot_read", "sensitive_read"}})
        findings.append(_make(
            "DYN_HONEYPOT_READ", "honeypot_access", "HIGH" if (external or sink_names) else "MEDIUM",
            f"Skill opened {len(reads)} honeypot/sensitive credential file(s)",
            "Decoy credential files (fake ~/.aws, ~/.ssh, ~/.npmrc ...) were opened during execution. "
            "A skill with no documented need for credentials should never touch them."
            + (" Outbound network activity was also attempted." if external else ""),
            {"paths": reads[:20], "monitors": sources, "outbound_attempted": sorted(external)},
            finding_id=f"DYN_HONEYPOT_READ:{','.join(reads[:3])}", path=reads[0]))

    # 6. Egress attempts (blocked by the sandbox, visible to the guard).
    for host, info in sorted(destinations.items()):
        severity = "MEDIUM" if info["classification"] == "external" else "LOW"
        if info["classification"] == "external" and suspicious_context:
            severity = "HIGH"
        findings.append(_make(
            "DYN_EGRESS_ATTEMPT", "network_egress_attempt", severity,
            f"Skill tried to reach {'external' if info['classification'] == 'external' else 'cluster-internal'} "
            f"destination {host}",
            "The sandbox only allows traffic to the controlled sink. This destination was contacted or resolved "
            "by the skill and is expected to have been blocked."
            + (" It followed access to honeypot data." if severity == "HIGH" else ""),
            {"host": host, "ports": sorted(info["ports"], key=str), "observed_by": sorted(info["sources"]),
             "event_types": sorted(info["types"])},
            finding_id=f"DYN_EGRESS_ATTEMPT:{host}", path=host))

    # 7. Dynamically generated code.
    dyn = [e for e in events if e.get("type") == "dynamic_exec"]
    if dyn:
        findings.append(_make(
            "DYN_DYNAMIC_EXEC", "obfuscated_execution", "MEDIUM",
            "Skill executed dynamically generated code at runtime",
            "exec()/eval() ran code built from a string (for example a decoded payload) directly from skill code.",
            {"events": dyn[:5]}, finding_id="DYN_DYNAMIC_EXEC", path=str(dyn[0].get("caller") or "")))
    return findings, derived


def _coverage_mode(commands: list, agent_actions: list, events: list) -> str:
    agent_seen = bool(agent_actions) or any(e.get("type") == "agent_error" for e in events)
    if agent_seen and commands:
        return "scripted+ollama_agent"
    return "ollama_agent" if agent_seen else "scripted"


def coverage_from_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    plan = next((e for e in events if e.get("type") == "execution_plan"), None)
    commands = [e for e in events if e.get("type") == "skill_command"]
    agent_actions = [e for e in events if e.get("type") == "agent_action"]
    ran_agent = bool(agent_actions) and any(a.get("tool") == "run_python" for a in agent_actions)
    return {
        "mode": _coverage_mode(commands, agent_actions, events),
        "entrypoint_found": bool(commands) or ran_agent,
        "commands_planned": len(plan.get("commands", [])) if plan else 0,
        "commands_run": len(commands) + sum(1 for a in agent_actions if a.get("tool") == "run_python"),
        "commands_failed": sum(1 for c in commands if c.get("exit_code") not in (0, None) or c.get("timed_out")),
        "timed_out": sum(1 for c in commands if c.get("timed_out")),
        "trace_available": bool(plan.get("trace_available")) if plan else False,
        "no_entrypoint": any(e.get("type") == "no_entrypoint" for e in events),
        "guard_enabled": bool(plan.get("guard", True)) if plan else False,
        "agent_errors": sum(1 for e in events if e.get("type") == "agent_error"),
    }


def collect_events(events: Iterable[dict[str, Any]], *, monitoring_tier: str, scan_token: str | None = None,
                   allowed_hosts: Iterable[str] = ()) -> DynamicResult:
    normalized = [event for event in events if isinstance(event, dict)]
    findings, derived = derive_findings(normalized, scan_token=scan_token, allowed_hosts=allowed_hosts)
    all_events = normalized + derived
    coverage = coverage_from_events(all_events)
    monitors = {
        "sink": True,
        "python_audit_guard": bool(coverage.get("guard_enabled")),
        "strace": bool(coverage.get("trace_available")),
        "tetragon": any(e.get("type") == "tetragon" for e in all_events),
    }
    return DynamicResult(status="complete", monitoring_tier=monitoring_tier, findings=findings,
                         events=all_events, coverage=coverage, monitors=monitors)
