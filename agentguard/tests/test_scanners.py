"""External scanner discovery and adapters, pinned to REAL captured output of both tools."""
import json
import stat
import sys
from pathlib import Path

from agentguard import orchestrator, scanners
from agentguard.normalize import normalize_cisco, normalize_nvidia

DATA = Path(__file__).parent / "data"
SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _fake_scanner(path: Path, report_file: Path, exit_code: int) -> Path:
    path.write_text(f"#!{sys.executable}\nimport sys\nif '--version' in sys.argv:\n    print('fake 1.0'); raise SystemExit(0)\n"
                    f"sys.stdout.write(open({str(report_file)!r}).read()); raise SystemExit({exit_code})\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def test_real_nvidia_output_normalizes():
    findings = normalize_nvidia(json.loads((DATA / "nvidia-real-output.json").read_text()), "2.12.0")
    assert len(findings) == 4
    top = next(f for f in findings if f.rule_id == "TT3")
    assert top.severity == "CRITICAL" and top.location.path == "scripts/tidy.py" and top.location.start_line == 15


def test_real_cisco_output_normalizes():
    findings = normalize_cisco(json.loads((DATA / "cisco-real-output.json").read_text()), "2.3.2")
    assert findings and all(f.tool == "cisco" and f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} for f in findings)


def test_discovery_order_and_disable_switch(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTGUARD_DISABLE_SCANNER_DISCOVERY")
    venvs = tmp_path / "venvs"
    exe = venvs / "skillspector" / "bin" / "skillspector"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("AGENTGUARD_VENV_DIR", str(venvs))
    monkeypatch.setenv("PATH", str(tmp_path / "nothing"))
    command, source = scanners.locate("nvidia")
    assert command == [str(exe), "scan"] and source.startswith("venv")
    assert scanners.locate("cisco")[0] is None  # not installed -> skipped, never an error
    monkeypatch.setenv("AGENTGUARD_NVIDIA_COMMAND", "/custom/skillspector scan")  # explicit env wins
    assert scanners.locate("nvidia") == (["/custom/skillspector", "scan"], "env AGENTGUARD_NVIDIA_COMMAND")
    monkeypatch.delenv("AGENTGUARD_NVIDIA_COMMAND")
    monkeypatch.setenv("AGENTGUARD_DISABLE_SCANNER_DISCOVERY", "1")
    assert scanners.locate("nvidia")[0] is None


def test_static_stage_runs_both_scanners_through_the_pipeline(tmp_path, monkeypatch):
    nvidia = _fake_scanner(tmp_path / "nv", DATA / "nvidia-real-output.json", 1)  # SkillSpector exits 1 on findings
    cisco = _fake_scanner(tmp_path / "ci", DATA / "cisco-real-output.json", 0)
    monkeypatch.setenv("AGENTGUARD_NVIDIA_COMMAND", str(nvidia))
    monkeypatch.setenv("AGENTGUARD_CISCO_COMMAND", str(cisco))
    result = orchestrator.scan(str(SAMPLES / "runtime-exfil-sink"), workspace_base=tmp_path / "ws", scan_mode="quick")
    runs = {run.tool: run for run in result.tool_runs}
    assert runs["nvidia"].status == "completed" and runs["cisco"].status == "completed"
    tools = {f.tool for f in result.findings}
    assert {"nvidia", "cisco", "agentguard"} <= tools
    assert result.stages["nvidia"]["status"] == "completed" and result.stages["cisco"]["status"] == "completed"


def test_missing_scanners_are_skipped_not_failed(tmp_path):
    result = orchestrator.scan(str(SAMPLES / "benign-csv-stats"), workspace_base=tmp_path / "ws", scan_mode="quick")
    assert {run.tool: run.status for run in result.tool_runs} == {"cisco": "skipped", "nvidia": "skipped"}
    assert result.scan_status == "complete"


def test_broken_scanner_is_reported_as_failed_and_scan_continues(tmp_path, monkeypatch):
    broken = tmp_path / "bad"
    broken.write_text(f"#!{sys.executable}\nprint('not json')\n")
    broken.chmod(0o755)
    monkeypatch.setenv("AGENTGUARD_NVIDIA_COMMAND", str(broken))
    result = orchestrator.scan(str(SAMPLES / "runtime-exfil-sink"), workspace_base=tmp_path / "ws", scan_mode="quick")
    assert result.stages["nvidia"]["status"] == "failed" and "reason" in result.stages["nvidia"]
    assert any(f.tool == "agentguard" for f in result.findings)  # native rules still ran


def test_nvidia_gets_a_collapsed_copy_when_input_is_padded_with_blank_lines(tmp_path, monkeypatch):
    skill = tmp_path / "padded"
    (skill / "scripts").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: padded\ndescription: x\n---\nhello\n")
    (skill / "scripts" / "run.py").write_text("print('a')\n" + "\n" * 100_000 + "import os\nprint(dict(os.environ))\n")
    seen = tmp_path / "seen.txt"
    scanner = tmp_path / "nv"
    scanner.write_text(f"#!{sys.executable}\nimport sys\nroot = sys.argv[2]\nopen({str(seen)!r}, 'w').write(root + ' ' + "
                       f"str(len(open(root + '/scripts/run.py').read().splitlines())))\nprint('{{\"issues\": []}}')\n")
    scanner.chmod(0o755)
    monkeypatch.setenv("AGENTGUARD_NVIDIA_COMMAND", f"{scanner} scan")
    result = orchestrator.scan(str(skill), workspace_base=tmp_path / "ws", scan_mode="quick")
    root, lines = seen.read_text().split()
    assert root.endswith("normalized-for-scanners") and int(lines) < 100
    assert "collapsed" in result.stages["nvidia"]["note"]
    assert any(f.rule_id == "AG006" for f in result.findings)  # native rule still inspected the original
    assert len((skill / "scripts" / "run.py").read_text().splitlines()) > 100_000  # original untouched
