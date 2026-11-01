from agentguard.gate import decide
from agentguard.models import Finding


def finding(tool: str, severity: str, category: str = "test") -> Finding:
    return Finding(tool, "id", "rule", category, severity, "message")


def test_gate_stops_for_clean_and_critical():
    assert not decide([]).escalate
    assert not decide([finding("agentguard", "CRITICAL")]).escalate


def test_gate_escalates_ambiguous_evidence():
    assert decide([finding("agentguard", "MEDIUM")]).escalate
    assert decide([finding("agentguard", "HIGH")]).escalate
    assert decide([finding("agentguard", "HIGH", "obfuscation")]).escalate


def test_gate_stops_for_independent_high_sources():
    result = decide([finding("cisco", "HIGH"), finding("nvidia", "HIGH")])
    assert not result.escalate
