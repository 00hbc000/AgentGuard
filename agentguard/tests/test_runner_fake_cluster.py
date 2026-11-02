"""Exercises agentguard.dynamic.runner.run() against a fake kubectl/docker/kind toolchain.

The fake `kubectl exec` runs the pod's commands locally (the real sandbox harness, guard, canaries
and sink server) against temp directories. This validates the host-side orchestration - preflight,
image reuse, manifests, isolation probes, honeypot preparation, execution, evidence collection and
cleanup - without a cluster. It does NOT validate NetworkPolicy enforcement, strace under the pod's
security context, or Tetragon; scripts/verify_sandbox.py covers those on a real kind cluster.
"""
import os
import stat
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from agentguard.dynamic import runner
from sandbox import sink_server
from sandbox.sink_server import SinkHandler

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
REPO = Path(__file__).resolve().parents[2]

KUBECTL = r'''#!%(python)s
import os, re, subprocess, sys
state = os.environ["FAKE_K8S_DIR"]
args = sys.argv[1:]
if args[:2] == ["-n", "agentguard-sandbox"] or args[:2] == ["-n", "kube-system"]:
    ns, args = args[1], args[2:]
else:
    ns = None
def log(line):
    with open(os.path.join(state, "calls.log"), "a") as handle:
        handle.write(line + "\n")
log(" ".join(args)[:200])
cmd = args[0] if args else ""
if cmd == "get":
    if args[1] == "nodes": print("node/fake"); sys.exit(0)
    if args[1] == "daemonset": sys.exit(1)
    if args[1] == "svc": print("10.96.0.5"); sys.exit(0)
    if args[1] == "pod" and "-l" in args: print("10.244.0.5"); sys.exit(0)
    if args[1] == "pod":
        print("sha256:fakeimage" if "imageID" in " ".join(args) else "127.0.0.1"); sys.exit(0)
    sys.exit(0)
if cmd == "apply":
    if args[-1] == "-":
        open(os.path.join(state, "pod.yaml"), "w").write(sys.stdin.read())
    sys.exit(0)
if cmd in {"set", "rollout", "wait"}: sys.exit(0)
if cmd == "delete":
    open(os.path.join(state, "deleted"), "w").write(" ".join(args)); sys.exit(0)
if cmd == "logs":
    path = os.path.join(state, "sink.log")
    sys.stdout.write(open(path).read() if os.path.exists(path) else ""); sys.exit(0)
if cmd == "exec":
    rest = args[args.index("--") + 1:]
    if rest[0] == "tar":
        sys.exit(subprocess.call(["tar", "xf", "-", "-C", os.path.join(state, "skill")]))
    if rest[0] == "mkdir": sys.exit(0)
    if rest[0] == "cat":
        path = os.path.join(state, "tmp", os.path.basename(rest[1]))
        if not os.path.exists(path): sys.exit(1)
        sys.stdout.write(open(path).read()); sys.exit(0)
    if rest[0] == "python" and rest[1] == "-c":
        probe = rest[2]
        if "1.1.1.1" in probe: sys.stderr.write("blocked"); sys.exit(1)   # no public internet
        sys.exit(0)                                                          # sink reachable
    if rest[0] == "python":
        script = os.path.join(%(repo)r, "sandbox", os.path.basename(rest[1]))
        manifest = open(os.path.join(state, "pod.yaml")).read()
        token = re.search(r"name: AGENTGUARD_SCAN_TOKEN\s+value: (\w+)", manifest).group(1)
        env = dict(os.environ, AGENTGUARD_SCAN_TOKEN=token,
                   AGENTGUARD_SKILL_DIR=os.path.join(state, "skill"),
                   AGENTGUARD_HONEYPOT_DIR=os.path.join(state, "honeypots"),
                   AGENTGUARD_TMP_DIR=os.path.join(state, "tmp"),
                   AGENTGUARD_SINK_URL="http://127.0.0.1:%%s/collect/%%s" %% (os.environ["FAKE_SINK_PORT"], token))
        sys.exit(subprocess.call([%(python)r, script] + rest[2:], env=env))
sys.exit(0)
'''
DOCKER = '''#!%(python)s
import os, sys
a = sys.argv[1:]
if a[:2] == ["image", "inspect"]: sys.exit(0)
if a and a[0] == "exec":
    tag = os.environ["AGENTGUARD_IMAGE_TAG"]
    print("docker.io/library/agentguard-sandbox   %%s   abc" %% tag)
    print("docker.io/library/agentguard-sink      %%s   def" %% tag)
sys.exit(0)
'''
KIND = "#!%(python)s\nimport sys\nsys.exit(0)\n"


@pytest.fixture()
def fake_cluster(tmp_path, monkeypatch):
    state = tmp_path / "state"
    for name in ("skill", "honeypots", "tmp"):
        (state / name).mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, template in (("kubectl", KUBECTL), ("docker", DOCKER), ("kind", KIND)):
        path = bin_dir / name
        path.write_text(template % {"python": sys.executable, "repo": str(REPO)})
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
    lines = []
    monkeypatch.setattr(sink_server, "print", lambda *a, **k: lines.append(" ".join(map(str, a))), raising=False)

    def flush_sink_log():
        (state / "sink.log").write_text("\n".join(lines) + "\n")

    server = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("PATH", str(bin_dir) + ":" + os.environ["PATH"])
    monkeypatch.setenv("FAKE_K8S_DIR", str(state))
    monkeypatch.setenv("FAKE_SINK_PORT", str(server.server_address[1]))
    monkeypatch.setenv("AGENTGUARD_IMAGE_TAG", "testtag")
    monkeypatch.setenv("AGENTGUARD_DYNAMIC_TIMEOUT", "120")
    # the sink log must be visible to `kubectl logs` as soon as the skill has talked to it
    real_logs = runner._events_from_logs
    monkeypatch.setattr(runner, "_events_from_logs", lambda *a, **k: (flush_sink_log(), real_logs(*a, **k))[1])
    yield state
    server.shutdown()


def calls(state):
    return (state / "calls.log").read_text().splitlines()


def test_malicious_skill_is_proven_critical_through_full_runner(fake_cluster):
    messages = []
    result = runner.run(SAMPLES / "runtime-exfil-evasive", progress=messages.append)
    assert result.status == "complete", result.error
    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["DYN_HONEYPOT_EXFIL"].severity == "CRITICAL"
    assert result.coverage["commands_run"] >= 1
    assert result.monitoring_tier == "fallback"
    assert any("honeypot" in m.lower() for m in messages)
    manifest = (fake_cluster / "pod.yaml").read_text()
    assert "AGENTGUARD_SCAN_TOKEN" in manifest and "readOnlyRootFilesystem: true" in manifest
    assert "runAsNonRoot: true" in manifest and "drop: [\"ALL\"]" in manifest
    assert (fake_cluster / "deleted").exists()  # pod is always cleaned up


def test_benign_skill_has_no_findings_through_full_runner(fake_cluster):
    result = runner.run(SAMPLES / "benign-csv-stats")
    assert result.status == "complete" and result.findings == []
    assert result.coverage["commands_run"] == 1
    assert any(call.startswith("delete") for call in calls(fake_cluster))


def test_isolation_proof_failure_aborts_before_running_the_skill(fake_cluster, monkeypatch):
    # make the "public internet" probe succeed -> NetworkPolicy is not enforced -> must refuse to run
    monkeypatch.setattr(runner, "_run_probe", lambda pod, target, timeout=20: (True, "reached"))
    with pytest.raises(runner.DynamicUnavailable, match="isolation proof failed"):
        runner.run(SAMPLES / "benign-csv-stats")
    assert (fake_cluster / "deleted").exists()
    assert not list((fake_cluster / "tmp").glob("agentguard-agent-events.jsonl"))  # skill never ran


def test_skill_files_are_copied_without_symlinks_or_git_dir(fake_cluster, tmp_path):
    skill = tmp_path / "skill"
    (skill / ".git").mkdir(parents=True)
    (skill / ".git" / "config").write_text("secret")
    (skill / "SKILL.md").write_text("---\nname: x\ndescription: x\n---\n")
    (skill / "link").symlink_to("/etc/passwd")
    runner.run(skill)
    copied = {p.name for p in (fake_cluster / "skill").rglob("*")}
    assert "SKILL.md" in copied and "link" not in copied and "config" not in copied


def test_exported_ollama_env_never_replaces_the_scripted_harness(fake_cluster, monkeypatch):
    # Regression: a shell with AGENTGUARD_AGENT_MODE=ollama used to disable the guard and run no commands.
    monkeypatch.setenv("AGENTGUARD_AGENT_MODE", "ollama")
    monkeypatch.setenv("AGENTGUARD_OLLAMA_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AGENTGUARD_OLLAMA_CIDR", "172.19.0.1/32")
    result = runner.run(SAMPLES / "runtime-exfil-evasive")  # sandbox mode: deep=False
    assert result.coverage["mode"] == "scripted" and result.coverage["guard_enabled"] is True
    assert result.coverage["agent_errors"] == 0
    assert {f.rule_id: f.severity for f in result.findings}["DYN_HONEYPOT_EXFIL"] == "CRITICAL"
    manifest = (fake_cluster / "pod.yaml").read_text()
    assert "AGENTGUARD_AGENT_MODE" not in manifest and "OLLAMA" not in manifest
    assert not any("sandbox-ollama-egress" in c for c in calls(fake_cluster))


def test_deep_mode_runs_scripted_harness_then_bounded_agent_without_failing_the_scan(fake_cluster, monkeypatch):
    monkeypatch.setenv("AGENTGUARD_AGENT_MODE", "ollama")
    monkeypatch.setenv("AGENTGUARD_OLLAMA_URL", "http://127.0.0.1:9")  # nothing listens: the agent must fail softly
    monkeypatch.setenv("AGENTGUARD_OLLAMA_CIDR", "172.19.0.1/32")
    monkeypatch.setenv("AGENTGUARD_AGENT_TIMEOUT", "60")
    result = runner.run(SAMPLES / "runtime-exfil-evasive", deep=True)
    assert result.status == "complete", result.error
    assert {f.rule_id: f.severity for f in result.findings}["DYN_HONEYPOT_EXFIL"] == "CRITICAL"
    assert result.coverage["commands_run"] >= 1 and result.coverage["guard_enabled"] is True
    assert result.coverage["mode"] == "scripted+ollama_agent" and result.coverage["agent_errors"] >= 1
    assert "AGENTGUARD_AGENT_MODE" in (fake_cluster / "pod.yaml").read_text()


def test_deep_mode_without_agent_configured_is_just_the_scripted_run(fake_cluster):
    result = runner.run(SAMPLES / "benign-csv-stats", deep=True)
    assert result.status == "complete" and result.findings == []
    assert result.coverage["mode"] == "scripted" and "AGENTGUARD_AGENT_MODE" not in (fake_cluster / "pod.yaml").read_text()
