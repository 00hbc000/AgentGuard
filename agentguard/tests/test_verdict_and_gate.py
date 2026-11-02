from agentguard.gate import decide
from agentguard.models import Finding
from agentguard.verdict import build_verdict


def payload(severity="INFO", findings=(), mode="quick", dynamic_stage=None, coverage=None, status="complete", reason=None):
    stages = {"mode": {"status": mode}}
    dynamic = None
    if dynamic_stage:
        stages["dynamic"] = {"status": dynamic_stage, "reason": reason}
        dynamic = {"coverage": coverage or {}, "monitoring_tier": "fallback"}
    return {"findings": list(findings), "aggregate_severity": severity, "stages": stages,
            "dynamic": dynamic, "scan_status": status}


def finding(rule, tool="agentguard", severity="HIGH"):
    return {"rule_id": rule, "tool": tool, "severity": severity}


def test_proven_exfiltration_is_malicious():
    verdict = build_verdict(payload("CRITICAL", [finding("DYN_HONEYPOT_EXFIL", "agentguard_sandbox", "CRITICAL")],
                                    "sandbox", "complete", {"commands_run": 1}))
    assert verdict["label"] == "malicious" and "proven" in verdict["headline"].lower()


def test_severity_maps_to_labels():
    assert build_verdict(payload("HIGH", [finding("AG001")]))["label"] == "high_risk"
    assert build_verdict(payload("MEDIUM", [finding("AG005", severity="MEDIUM")]))["label"] == "suspicious"
    assert build_verdict(payload("LOW", [finding("AG008", severity="LOW")]))["label"] == "low_risk"
    assert build_verdict(payload())["label"] == "no_findings"


def test_sandbox_with_no_commands_run_is_inconclusive_not_safe():
    verdict = build_verdict(payload("INFO", mode="sandbox", dynamic_stage="complete", coverage={"commands_run": 0}))
    assert verdict["label"] == "inconclusive"
    assert "no commands" in verdict["reason"]


def test_failed_sandbox_is_inconclusive_and_says_why():
    verdict = build_verdict(payload("INFO", mode="sandbox", dynamic_stage="failed", reason="kubectl missing", status="error"))
    assert verdict["label"] == "inconclusive" and "kubectl missing" in verdict["reason"]


def test_sandbox_that_ran_commands_and_found_nothing_is_no_findings():
    verdict = build_verdict(payload("INFO", mode="sandbox", dynamic_stage="complete", coverage={"commands_run": 2}))
    assert verdict["label"] == "no_findings"


def test_gate_escalates_clean_skill_that_ships_scripts():
    assert decide([], has_executable_content=True).escalate
    assert not decide([]).escalate


def test_gate_still_stops_on_critical():
    critical = Finding(tool="t", finding_id="1", rule_id="R", category="c", severity="CRITICAL", message="m")
    assert not decide([critical], has_executable_content=True).escalate
