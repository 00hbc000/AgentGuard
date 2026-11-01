from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ..models import Finding, Location


@dataclass
class DynamicResult:
    status: str
    monitoring_tier: str
    findings: list[Finding] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "monitoring_tier": self.monitoring_tier,
            "finding_count": len(self.findings),
            "findings": [item.to_dict() for item in self.findings],
            "events": self.events,
            "error": self.error,
        }


def _honeypot_finding(event: dict[str, Any]) -> Finding | None:
    if event.get("type") != "honeypot_exfiltration" or not event.get("honeypot_hit"):
        return None
    path = str(event.get("path") or "honeypot")
    return Finding(
        tool="agentguard_sandbox",
        tool_version="0.1.0",
        finding_id=f"DYN_HONEYPOT_EXFIL:{path}",
        rule_id="DYN_HONEYPOT_EXFIL",
        category="honeypot_exfiltration",
        severity="CRITICAL",
        message="Sandboxed skill accessed a honeypot credential and attempted external transmission",
        description="A monitored honeypot file was read and data was sent to an external sink.",
        confidence=1.0,
        remediation="Do not install or run this skill.",
        location=Location(path=path, start_line=None),
        evidence={"event": event, "proven": True},
        raw_finding=event,
    )


def collect_events(events: Iterable[dict[str, Any]], *, monitoring_tier: str) -> DynamicResult:
    normalized = [event for event in events if isinstance(event, dict)]
    findings: list[Finding] = []
    for event in normalized:
        finding = _honeypot_finding(event)
        if finding is not None:
            findings.append(finding)
    return DynamicResult(
        status="complete",
        monitoring_tier=monitoring_tier,
        findings=findings,
        events=normalized,
    )
