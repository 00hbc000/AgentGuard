from agentguard.web import _page, _render
from agentguard.web import _PAGE


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


def test_web_form_offers_skillward_style_scan_modes():
    assert 'value="quick"' in _PAGE
    assert 'value="sandbox"' in _PAGE
    assert 'value="deep"' in _PAGE
    assert 'Sandbox and Deep Trace execute inside Kubernetes.' in _PAGE
    assert 'fetch("/api/jobs"' in _PAGE
    assert 'scan_mode:scanMode' in _PAGE


def test_web_page_marks_selected_scan_mode():
    page = _page(_PAGE, scan_mode="sandbox")
    assert 'value="sandbox" checked' in page
    assert 'value="quick" checked' not in page
