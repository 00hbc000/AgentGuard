from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tarfile
import time
import uuid
from io import BytesIO
from pathlib import Path

from .collector import DynamicResult, collect_events


class DynamicUnavailable(RuntimeError):
    pass


def monitoring_tier() -> str:
    return os.environ.get("AGENTGUARD_MONITORING_TIER", "fallback")


def _run(command: list[str], *, input_text: str | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command, input=input_text, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DynamicUnavailable(f"Command timed out: {' '.join(command)}") from exc
    except OSError as exc:
        raise DynamicUnavailable(f"Could not run {' '.join(command)}: {exc}") from exc


def _require_tools() -> None:
    missing = [name for name in ("docker", "kind", "kubectl") if shutil.which(name) is None]
    if missing:
        raise DynamicUnavailable(
            "Dynamic sandbox unavailable; missing required command(s): "
            + ", ".join(missing) + ". No skill code was executed."
        )


def _check(result: subprocess.CompletedProcess[str], action: str) -> str:
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise DynamicUnavailable(f"{action} failed: {detail or 'no diagnostic output'}")
    return result.stdout


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _build_images(cluster: str) -> None:
    root = _repo_root()
    _check(_run(["docker", "build", "-t", "agentguard-sandbox:local", str(root / "sandbox")], timeout=300), "Building sandbox image")
    _check(_run(["docker", "build", "-f", str(root / "sandbox" / "Sink.Dockerfile"),
                 "-t", "agentguard-sink:local", str(root / "sandbox")], timeout=300), "Building sink image")
    _check(_run(["kind", "load", "docker-image", "agentguard-sandbox:local", "--name", cluster], timeout=180), "Loading sandbox image")
    _check(_run(["kind", "load", "docker-image", "agentguard-sink:local", "--name", cluster], timeout=180), "Loading sink image")


def _apply_manifests() -> None:
    root = _repo_root()
    for name in ("namespace.yaml", "sink.yaml", "network-policy.yaml"):
        _check(_run(["kubectl", "apply", "-f", str(root / "k8s" / name)], timeout=60), f"Applying {name}")
    if os.environ.get("AGENTGUARD_AGENT_MODE") == "ollama":
        cidr = os.environ.get("AGENTGUARD_OLLAMA_CIDR")
        if not cidr:
            raise DynamicUnavailable("AGENTGUARD_OLLAMA_CIDR is required for Ollama egress allow-listing")
        policy = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandbox-ollama-egress
  namespace: agentguard-sandbox
spec:
  podSelector:
    matchLabels:
      agentguard.io/role: skill-sandbox
  policyTypes: [Egress]
  egress:
  - to:
    - ipBlock:
        cidr: {cidr}
    ports:
    - protocol: TCP
      port: 11434
"""
        _check(_run(["kubectl", "apply", "-f", "-"], input_text=policy, timeout=60), "Applying Ollama egress policy")
    _check(_run([
        "kubectl", "-n", "agentguard-sandbox", "rollout", "status",
        "deployment/agentguard-sink", "--timeout=90s",
    ], timeout=120), "Waiting for sink")


def _monitoring_tier() -> str:
    probe = _run(["kubectl", "-n", "kube-system", "get", "daemonset", "tetragon", "-o", "name"])
    return "tetragon" if probe.returncode == 0 and probe.stdout.strip() else "fallback"


def _run_probe(pod: str, target: str, timeout: int = 20) -> tuple[bool, str]:
    result = _run(["kubectl", "-n", "agentguard-sandbox", "exec", pod, "--", "python", "-c", target], timeout=timeout)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def _create_pod(pod: str) -> None:
    agent_env = ""
    if os.environ.get("AGENTGUARD_AGENT_MODE") == "ollama":
        agent_env = f"""    - name: AGENTGUARD_AGENT_MODE
      value: ollama
    - name: AGENTGUARD_OLLAMA_URL
      value: {os.environ["AGENTGUARD_OLLAMA_URL"]}
    - name: AGENTGUARD_OLLAMA_MODEL
      value: {os.environ.get("AGENTGUARD_OLLAMA_MODEL", "qwen2.5:7b")}
"""
    manifest = f"""apiVersion: v1
kind: Pod
metadata:
  name: {pod}
  namespace: agentguard-sandbox
  labels:
    agentguard.io/role: skill-sandbox
spec:
  restartPolicy: Never
  containers:
  - name: skill
    image: agentguard-sandbox:local
    imagePullPolicy: IfNotPresent
    command: ["sleep", "3600"]
    env:
    - name: AGENTGUARD_SINK_URL
      value: http://agentguard-sink.agentguard-sandbox.svc.cluster.local:8080
{agent_env}    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: false
      capabilities:
        drop: ["ALL"]
"""
    _check(_run(["kubectl", "apply", "-f", "-"], input_text=manifest, timeout=60), "Creating sandbox pod")
    _check(_run(["kubectl", "-n", "agentguard-sandbox", "wait", "--for=condition=Ready", f"pod/{pod}", "--timeout=90s"], timeout=120), "Waiting for sandbox pod")


def _copy_skill(root: Path, pod: str) -> None:
    archive = BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for path in root.rglob("*"):
            if path.is_file():
                info = tar.gettarinfo(str(path), arcname=str(path.relative_to(root)))
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with path.open("rb") as stream:
                    tar.addfile(info, stream)
    archive.seek(0)
    try:
        process = subprocess.run(
            ["kubectl", "-n", "agentguard-sandbox", "exec", "-i", pod, "--", "tar", "xf", "-", "-C", "/skill"],
            input=archive.read(), capture_output=True, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DynamicUnavailable(f"Copying skill into sandbox failed: {exc}") from exc
    if process.returncode:
        detail = (process.stderr or process.stdout).decode(errors="replace").strip()
        raise DynamicUnavailable(f"Copying skill into sandbox failed: {detail or 'no diagnostic output'}")


def _events_from_logs() -> list[dict]:
    logs = _run(["kubectl", "-n", "agentguard-sandbox", "logs", "deployment/agentguard-sink"], timeout=30)
    events = []
    for line in logs.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _events_from_pod(pod: str) -> list[dict]:
    result = _run(["kubectl", "-n", "agentguard-sandbox", "exec", pod, "--",
                   "cat", "/tmp/agentguard-agent-events.jsonl"], timeout=30)
    if result.returncode:
        return []
    events = []
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def run(root: Path) -> DynamicResult:
    """Run the skill in a kind Kubernetes pod with sink-only egress."""
    _require_tools()
    cluster = os.environ.get("AGENTGUARD_KIND_CLUSTER", "agentguard")
    namespace = "agentguard-sandbox"
    pod = f"agentguard-run-{uuid.uuid4().hex[:8]}"
    _build_images(cluster)
    _apply_manifests()
    tier = _monitoring_tier()
    try:
        _create_pod(pod)
        _check(_run(["kubectl", "-n", namespace, "exec", pod, "--", "mkdir", "-p", "/skill", "/honeypots"], timeout=30), "Preparing sandbox")
        _copy_skill(root, pod)
        _check(_run(["kubectl", "-n", namespace, "exec", pod, "--", "sh", "-c", "printf 'synthetic-honeypot\\n' > /honeypots/aws-credentials"], timeout=30), "Creating honeypot")
        internet_ok, internet_detail = _run_probe(
            pod,
            "import socket; socket.create_connection(('1.1.1.1', 80), 3)",
        )
        if internet_ok:
            raise DynamicUnavailable(
                "NetworkPolicy isolation proof failed: sandbox reached the public internet. "
                f"Probe output: {internet_detail}"
            )
        sink_ok, sink_detail = _run_probe(
            pod,
            "import socket; socket.create_connection(('agentguard-sink.agentguard-sandbox.svc.cluster.local', 8080), 3)",
        )
        if not sink_ok:
            raise DynamicUnavailable(
                "NetworkPolicy sink allow-list proof failed: sandbox could not reach the sink. "
                f"Probe output: {sink_detail}"
            )
        prepare = _run(["kubectl", "-n", namespace, "exec", pod, "--", "python", "/opt/agentguard/run_skill.py", "--phase", "prepare"], timeout=60)
        if prepare.returncode:
            return DynamicResult("error", tier, events=[{"type": "prepare_error", "stderr": prepare.stderr}], error="Sandbox preparation failed")
        command = os.environ.get("AGENTGUARD_ENTRYPOINT", "")
        args = ["python", "/opt/agentguard/run_skill.py", "--phase", "execute"]
        if command:
            args.extend(["--command", command])
        execute = _run(["kubectl", "-n", namespace, "exec", pod, "--", *args], timeout=int(os.environ.get("AGENTGUARD_DYNAMIC_TIMEOUT", "120")))
        events = _events_from_logs()
        events.extend(_events_from_pod(pod))
        trace = _run(["kubectl", "-n", namespace, "exec", pod, "--", "cat", "/tmp/agentguard-trace"], timeout=30)
        trace_text = trace.stdout
        if "/honeypots/aws-credentials" in trace_text and events:
            events.append({
                "type": "honeypot_exfiltration",
                "honeypot_hit": True,
                "path": "/honeypots/aws-credentials",
                "destination": "agentguard-sink",
                "monitoring_tier": tier,
            })
        if execute.returncode:
            events.append({"type": "execution_error", "exit_code": execute.returncode, "stderr": execute.stderr[-2000:]})
        return collect_events(events, monitoring_tier=tier)
    finally:
        _run(["kubectl", "-n", namespace, "delete", "pod", pod, "--ignore-not-found=true", "--wait=false"], timeout=30)


def run_demo(root: Path) -> DynamicResult:
    """Return a clearly synthetic result for UI and collector demonstrations."""
    if not root.is_dir():
        raise DynamicUnavailable(f"Dynamic sandbox input is not a directory: {root}")
    return collect_events(
        [{"type": "honeypot_exfiltration", "honeypot_hit": True, "path": "/honeypots/aws-credentials",
          "destination": "demo-sink.invalid", "synthetic": True}],
        monitoring_tier="demo_synthetic",
    )
