from agentguard.normalize import normalize_cisco, normalize_nvidia


def test_nvidia_fingerprint_ignores_random_finding_id():
    base = {"rule_id": "P1", "severity": "HIGH", "message": "same   message", "location": {"file": "SKILL.md", "start_line": 4}}
    first = normalize_nvidia({"issues": [{**base, "finding_id": "random-a"}]})[0]
    second = normalize_nvidia({"issues": [{**base, "finding_id": "random-b"}]})[0]
    assert first.fingerprint == second.fingerprint
    assert first.raw_finding["finding_id"] == "random-a"
    assert "random-a" not in first.to_dict()


def test_severity_mapping_includes_none_to_info():
    assert normalize_nvidia({"issues": [{"rule_id": "R", "severity": "NONE", "message": "x"}]})[0].severity == "INFO"
    assert normalize_cisco({"findings": [{"rule_id": "R", "severity": "CRITICAL", "title": "x"}]})[0].severity == "CRITICAL"
