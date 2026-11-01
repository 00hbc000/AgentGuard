from agentguard.web import _render


def test_web_renders_gate_and_dynamic_tier():
    page = _render({
        "aggregate_severity": "CRITICAL",
        "scan_status": "complete",
        "findings": [],
        "tools_used": ["agentguard", "agentguard_sandbox"],
        "decision_gate": {"escalate": True, "reason": "ambiguous"},
        "dynamic": {
            "status": "complete",
            "monitoring_tier": "demo_synthetic",
            "finding_count": 1,
            "events": [{"type": "honeypot_exfiltration"}],
        },
    })
    assert "Decision gate" in page
    assert "demo_synthetic" in page
    assert "honeypot_exfiltration" in page
