"""The public runtime sample group and the report script that runs it (no cluster needed)."""
import importlib.util
from pathlib import Path

from agentguard import ingest, samples

ROOT = Path(__file__).resolve().parents[2]


def _load_eval():
    spec = importlib.util.spec_from_file_location("eval_public_dynamic", ROOT / "scripts" / "eval_public_dynamic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _runtime():
    return [s for s in samples.SAMPLES if s.get("runtime")]


def test_public_runtime_group_is_well_formed():
    items = _runtime()
    assert len(items) == 12
    ids = [s["id"] for s in items]
    assert len(set(ids)) == len(ids) and all(i.startswith("msb-") and "_" not in i for i in ids)
    for item in items:
        assert item["kind"] == "remote" and item["group"] == samples.MSB_GROUP
        assert item["url"].startswith("https://github.com/lxyeternal/MalSkillBench/tree/main/Dataset/Skills/malware/")
        ingest._validate_remote_url(item["url"])  # must be an accepted source
        assert samples.resolve_source(item["id"]) == item["url"]
    assert {s["id"] for s in items if "Limit case" in s["shows"]} == {"msb-base64-payload", "msb-continuous-learning"}


def test_runtime_group_is_not_pulled_into_existing_batches():
    # The dashboard's "all malicious" button excludes runtime samples; the API flags them explicitly.
    listing = {s["id"]: s for s in samples.public_listing()}
    assert listing["msb-gen-docs"]["runtime"] is True
    assert "runtime" not in listing["runtime-exfil-sink"]
    assert not any("msb-" in s["id"] for s in samples.SAMPLES if not s.get("runtime"))


def test_report_summary_and_table_make_no_assertions():
    module = _load_eval()
    item = samples.get("msb-docker-expert")
    report = {
        "findings": [
            {"tool": "cisco", "severity": "LOW", "rule_id": "UNDECLARED_NETWORK_DESTINATION"},
            {"tool": "agentguard_sandbox", "severity": "HIGH", "rule_id": "DYN_ENV_EXPOSED"},
            {"tool": "agentguard_sandbox", "severity": "MEDIUM", "rule_id": "DYN_HONEYPOT_READ"},
        ],
        "stages": {"dynamic": {"status": "complete"}},
        "dynamic": {"coverage": {"commands_run": 1, "commands_failed": 0, "timed_out": 0}},
        "verdict": {"label": "high_risk"},
    }
    row = module.summarize(item, report)
    assert row["static"] == {"agentguard": "-", "cisco": "LOW", "nvidia": "-"}
    assert row["dynamic"] == ["DYN_ENV_EXPOSED:HIGH", "DYN_HONEYPOT_READ:MEDIUM"]
    table = module.render([row, module.summarize(item, {"error": "boom"})])
    assert "docker-expert" in table and "DYN_ENV_EXPOSED:HIGH" in table and "scan failed: boom" in table
