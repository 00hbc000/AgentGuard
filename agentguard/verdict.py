"""Plain-language verdict derived from findings, stages and dynamic coverage."""
from __future__ import annotations

from typing import Any

_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def build_verdict(payload: dict[str, Any]) -> dict[str, Any]:
    """Return ``{"label", "headline", "reason", "recommendation", "evidence"}``.

    Labels: ``malicious`` (proven), ``high_risk``, ``suspicious``, ``no_findings`` and
    ``inconclusive``. ``no_findings`` is never reported as "safe": static rules and a
    bounded sandbox run can miss things, and the report says which stages actually ran.
    """
    findings = payload.get("findings", [])
    severity = payload.get("aggregate_severity", "INFO")
    dynamic = payload.get("dynamic") or {}
    stages = payload.get("stages", {})
    mode = stages.get("mode", {}).get("status", "quick")
    coverage = dynamic.get("coverage") or {}
    dynamic_status = (stages.get("dynamic") or {}).get("status")
    proven = [f for f in findings if f.get("rule_id") == "DYN_HONEYPOT_EXFIL"]
    static_hits = [f for f in findings if f.get("tool") != "agentguard_sandbox"]
    dynamic_hits = [f for f in findings if f.get("tool") == "agentguard_sandbox"]
    evidence = {
        "static_findings": len(static_hits), "dynamic_findings": len(dynamic_hits),
        "dynamic_stage": dynamic_status or "not_requested",
        "dynamic_commands_run": coverage.get("commands_run"),
        "monitoring_tier": dynamic.get("monitoring_tier"),
    }
    gaps = []
    if dynamic_status == "failed":
        gaps.append("the sandbox stage failed: " + str((stages.get("dynamic") or {}).get("reason", "unknown")))
    elif dynamic_status == "complete" and coverage and not coverage.get("commands_run"):
        gaps.append("the sandbox ran no commands (no runnable entrypoint was found)")
    elif dynamic_status == "skipped":
        gaps.append("the decision gate skipped the sandbox")
    elif not dynamic_status:
        gaps.append("no runtime analysis was requested (Quick Scan)")
    if payload.get("scan_status") in {"error", "partial", "incomplete"} and dynamic_status != "failed":
        gaps.append(f"scan status is {payload.get('scan_status')}")

    if proven:
        return {"label": "malicious", "headline": "MALICIOUS - exfiltration proven at runtime",
                "reason": "A honeypot secret planted for this scan was observed in sink traffic.",
                "recommendation": "Do not install or run this skill.", "evidence": evidence, "gaps": gaps}
    rank = _ORDER.get(severity, 0)
    if rank >= 4:
        return {"label": "malicious", "headline": "CRITICAL findings", "reason": "Critical evidence was found.",
                "recommendation": "Do not install or run this skill.", "evidence": evidence, "gaps": gaps}
    if rank == 3:
        return {"label": "high_risk", "headline": "HIGH RISK",
                "reason": f"{len(findings)} finding(s); highest severity HIGH.",
                "recommendation": "Do not install until each HIGH finding is reviewed and explained.",
                "evidence": evidence, "gaps": gaps}
    if rank == 2:
        return {"label": "suspicious", "headline": "SUSPICIOUS",
                "reason": f"{len(findings)} finding(s); highest severity MEDIUM.",
                "recommendation": "Review the findings; run a Sandbox Scan if it was not already run.",
                "evidence": evidence, "gaps": gaps}
    if gaps and mode != "quick":
        return {"label": "inconclusive", "headline": "INCONCLUSIVE",
                "reason": "No findings, but coverage was incomplete: " + "; ".join(gaps).rstrip(".") + ".",
                "recommendation": "Absence of findings is not evidence of safety here. Fix the gap and re-scan.",
                "evidence": evidence, "gaps": gaps}
    if rank == 1:
        return {"label": "low_risk", "headline": "LOW-SEVERITY NOTES ONLY",
                "reason": f"{len(findings)} low-severity finding(s); nothing above LOW.",
                "recommendation": "Skim the notes; they are usually warnings or documentation mentions."
                                  + (" Gaps: " + "; ".join(gaps).rstrip(".") + "." if gaps else ""),
                "evidence": evidence, "gaps": gaps}
    return {"label": "no_findings", "headline": "NO FINDINGS",
            "reason": "No rule or runtime observation flagged this skill."
                      + (" Gaps: " + "; ".join(gaps) + "." if gaps else ""),
            "recommendation": "No known-bad behaviour was observed; this is not a guarantee of safety.",
            "evidence": evidence, "gaps": gaps}
