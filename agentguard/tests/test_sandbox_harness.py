"""End-to-end test of the in-pod harness without Kubernetes.

The harness, runtime guard, canaries, sink server and collector all run for real; only the
pod boundary is replaced by temp directories. Sample skills are the repository's synthetic
`samples/` (they only ever talk to the local test sink or reserved `.invalid` hosts).
"""
import json
import shutil
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from agentguard.dynamic.collector import collect_events
from sandbox import canary, execution, sink_server
from sandbox.sink_server import SinkHandler

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
TOKEN = "a1b2c3d4" * 4


@pytest.fixture()
def pod(tmp_path, monkeypatch):
    skill, honeypots, tmp = tmp_path / "skill", tmp_path / "honeypots", tmp_path / "tmp"
    for directory in (skill, honeypots, tmp):
        directory.mkdir()
    monkeypatch.setattr(execution, "SKILL_DIR", skill)
    monkeypatch.setattr(execution, "HONEYPOT_DIR", honeypots)
    monkeypatch.setattr(execution, "TMP_DIR", tmp)
    monkeypatch.setattr(execution, "EVENTS_FILE", tmp / "agentguard-agent-events.jsonl")
    monkeypatch.setattr(execution, "TRACE_FILE", tmp / "agentguard-trace")
    monkeypatch.setattr(execution, "strace_available", lambda: False)
    monkeypatch.setenv("AGENTGUARD_SCAN_TOKEN", TOKEN)
    execution.create_honeypots(TOKEN)
    return skill


@pytest.fixture()
def sink(monkeypatch):
    """The real sink handler on a loopback port; yields a function returning its logged events."""
    lines: list[str] = []
    monkeypatch.setattr(sink_server, "print", lambda *args, **kwargs: lines.append(" ".join(map(str, args))),
                        raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("AGENTGUARD_SINK_URL", f"http://127.0.0.1:{server.server_address[1]}/collect/{TOKEN}")
    yield lambda: [json.loads(line) for line in lines if line.startswith("{")]
    server.shutdown()


def run_sample(name: str, pod: Path) -> list[dict]:
    shutil.copytree(SAMPLES / name, pod, dirs_exist_ok=True)
    assert execution.execute(TOKEN, timeout=20) == 0
    return [json.loads(line) for line in execution.EVENTS_FILE.read_text().splitlines()]


def test_canary_detects_plain_url_base64_and_hex_copies():
    secret = canary.canary_value(TOKEN, "AWS_SECRET_ACCESS_KEY")
    import base64
    for blob in (secret, f"x=1&k={secret}", base64.b64encode(secret.encode()).decode(),
                 base64.urlsafe_b64encode(f"{{'k': '{secret}'}}".encode()).decode(), secret.encode().hex()):
        hits = canary.find_canaries(blob)
        assert hits and hits[0]["token"] == TOKEN, blob
    assert canary.find_canaries("AGCANARY-notatoken-X and harmless text") == []


def test_benign_skill_has_no_findings_and_runs_documented_command(pod):
    events = run_sample("benign-csv-stats", pod)
    commands = [e for e in events if e["type"] == "skill_command"]
    assert len(commands) == 1 and commands[0]["exit_code"] == 0
    assert "rows=3 columns=3" in commands[0]["stdout"]  # SKILL.md placeholder replaced by a sample CSV
    result = collect_events(events, monitoring_tier="fallback", scan_token=TOKEN)
    assert result.findings == []
    assert result.coverage["commands_run"] == 1


def test_env_dump_is_detected_from_output(pod):
    events = run_sample("runtime-env-dump", pod)
    result = collect_events(events, monitoring_tier="fallback", scan_token=TOKEN)
    assert {f.rule_id for f in result.findings} == {"DYN_ENV_EXPOSED"}
    assert result.findings[0].severity == "HIGH"


def test_exfiltration_to_sink_is_proven_critical(pod, sink):
    events = run_sample("runtime-exfil-sink", pod)
    result = collect_events(events + sink(), monitoring_tier="fallback", scan_token=TOKEN)
    rules = {f.rule_id: f for f in result.findings}
    assert rules["DYN_HONEYPOT_EXFIL"].severity == "CRITICAL"
    assert rules["DYN_HONEYPOT_EXFIL"].evidence["proven"] is True
    assert "AWS_SECRET_ACCESS_KEY" in rules["DYN_HONEYPOT_EXFIL"].evidence["canary_names"]
    assert "DYN_HONEYPOT_READ" in rules
    assert "DYN_EXFIL_ATTEMPT" not in rules  # already covered by the sink proof


def test_evasive_skill_is_caught_only_at_runtime(pod, sink):
    from pathlib import Path as P
    from agentguard.custom_rules import scan_directory
    assert scan_directory(SAMPLES / "runtime-exfil-evasive") == []  # static analysis is blind to it
    events = run_sample("runtime-exfil-evasive", pod)
    result = collect_events(events + sink(), monitoring_tier="fallback", scan_token=TOKEN)
    severities = {f.rule_id: f.severity for f in result.findings}
    assert severities["DYN_HONEYPOT_EXFIL"] == "CRITICAL"
    assert severities["DYN_HONEYPOT_READ"] == "HIGH"


def test_blocked_external_exfiltration_is_reported_as_attempt_not_proof(pod):
    """No sink running: the .invalid host cannot be reached, but the guard still saw the secret leave."""
    events = run_sample("runtime-exfil-external", pod)
    result = collect_events(events, monitoring_tier="fallback", scan_token=TOKEN)
    rules = {f.rule_id: f for f in result.findings}
    assert "DYN_HONEYPOT_EXFIL" not in rules
    assert rules["DYN_EXFIL_ATTEMPT"].severity == "HIGH"
    assert "metrics.wordcount.invalid" in rules["DYN_EXFIL_ATTEMPT"].message
    assert rules["DYN_EGRESS_ATTEMPT"].severity == "HIGH"


def test_sink_events_for_other_scans_are_not_attributed(pod):
    other = canary.canary_value("f" * 32, "AWS_SECRET_ACCESS_KEY")
    event = {"type": "network_sink", "host": "x", "canary_hits": canary.find_canaries(other)}
    result = collect_events([event], monitoring_tier="fallback", scan_token=TOKEN)
    assert result.findings == []


def test_honeypot_read_without_exfiltration_is_not_critical():
    events = [{"type": "honeypot_read", "source": "strace", "path": "/honeypots/home/.aws/credentials"}]
    result = collect_events(events, monitoring_tier="fallback", scan_token=TOKEN)
    assert [(f.rule_id, f.severity) for f in result.findings] == [("DYN_HONEYPOT_READ", "MEDIUM")]


def test_no_entrypoint_is_reported_as_a_coverage_gap(pod):
    (pod / "SKILL.md").write_text("---\nname: prompt-only\ndescription: x\n---\nJust instructions.\n")
    assert execution.execute(TOKEN) == 0
    events = [json.loads(line) for line in execution.EVENTS_FILE.read_text().splitlines()]
    result = collect_events(events, monitoring_tier="fallback", scan_token=TOKEN)
    assert result.coverage["no_entrypoint"] is True and result.coverage["commands_run"] == 0


def test_dataclass_exec_is_not_reported_as_dynamic_exec(pod):
    (pod / "SKILL.md").write_text("---\nname: dc\ndescription: x\n---\n```\npython run.py\n```\n")
    (pod / "run.py").write_text("from dataclasses import dataclass\n@dataclass\nclass A:\n    x: int\nprint(A(1))\n")
    assert execution.execute(TOKEN) == 0
    events = [json.loads(line) for line in execution.EVENTS_FILE.read_text().splitlines()]
    assert not [e for e in events if e["type"] == "dynamic_exec"]


def test_decode_and_exec_is_reported_as_dynamic_exec(pod):
    (pod / "SKILL.md").write_text("---\nname: dx\ndescription: x\n---\n")
    (pod / "run.py").write_text("import base64\nexec(base64.b64decode('cHJpbnQoMSsxKQ=='))\n")
    assert execution.execute(TOKEN) == 0
    events = [json.loads(line) for line in execution.EVENTS_FILE.read_text().splitlines()]
    assert [e for e in events if e["type"] == "dynamic_exec"]


def test_strace_parser_extracts_honeypot_opens_and_external_connects():
    text = "\n".join([
        '123 openat(AT_FDCWD, "/honeypots/home/.aws/credentials", O_RDONLY|O_CLOEXEC) = 3',
        '123 openat(AT_FDCWD, "/honeypots/home/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file)',
        '123 connect(4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 EINPROGRESS',
        '123 connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("10.96.0.10")}, 16) = 0',
        '123 connect(6, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
    ])
    events = execution.parse_strace(text, Path("/honeypots"))
    assert [e["type"] for e in events] == ["honeypot_read", "network_attempt", "network_attempt"]
    assert events[1]["external"] is True and events[2]["external"] is False
    result = collect_events(events, monitoring_tier="fallback")
    rules = {f.rule_id: f.severity for f in result.findings}
    assert rules["DYN_HONEYPOT_READ"] == "HIGH"       # opened a decoy and tried an external connect
    assert rules["DYN_EGRESS_ATTEMPT"] == "HIGH"
    assert len([f for f in result.findings if f.rule_id == "DYN_EGRESS_ATTEMPT"]) == 1  # private DNS ignored
