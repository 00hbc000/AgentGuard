from agentguard.dynamic.collector import collect_events
from agentguard.normalize import aggregate_severity


def test_honeypot_exfiltration_is_critical_and_proven():
    result = collect_events(
        [{"type": "honeypot_exfiltration", "honeypot_hit": True, "path": "/root/.aws/credentials"}],
        monitoring_tier="fallback",
    )
    assert result.monitoring_tier == "fallback"
    assert result.findings[0].tool == "agentguard_sandbox"
    assert result.findings[0].rule_id == "DYN_HONEYPOT_EXFIL"
    assert result.findings[0].severity == "CRITICAL"
    assert result.findings[0].confidence == 1.0
    assert aggregate_severity(result.findings) == "CRITICAL"
