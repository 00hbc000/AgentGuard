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


def test_nvidia_native_id_and_explanation_are_preserved():
    finding = normalize_nvidia({"issues": [{
        "id": "PE3", "pattern": "Credential Access", "finding": "~/.aws/credentials",
        "severity": "HIGH", "confidence": 0.9,
        "explanation": "Credential file access detected.",
        "code_snippet": "open(path)",
        "location": {"file": "SKILL.md", "start_line": 9},
    }]})[0]
    payload = finding.to_dict()
    assert finding.rule_id == "PE3"
    assert finding.message == "Credential Access"
    assert finding.description == "Credential file access detected."
    assert "Credential file access detected." in payload["evidence"]
    assert payload["file_path"] == "SKILL.md"
    assert payload["line_number"] == 9
