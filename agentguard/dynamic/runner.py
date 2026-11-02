from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tarfile
import time
import uuid
from datetime import datetime, timezone
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


def _build_images(cluster: str) -> tuple[str, str]:
    root = _repo_root()
    tag = os.environ.get("AGENTGUARD_IMAGE_TAG") or f"{uuid.uuid4().hex[:12]}"
    sandbox_image = f"agentguard-sandbox:{tag}"
    sink_image = f"agentguard-sink:{tag}"
    build_args = ["--build-arg", f"AGENTGUARD_BUILD_TAG={tag}"]
    _check(_run(["docker", "build", *build_args, "-t", sandbox_image, str(root / "sandbox")], timeout=300), "Building sandbox image")
    _check(_run(["docker", "build", "-f", str(root / "sandbox" / "Sink.Dockerfile"),
                 *build_args, "-t", sink_image, str(root / "sandbox")], timeout=300), "Building sink image")
    _check(_run(["kind", "load", "docker-image", sandbox_image, "--name", cluster], timeout=180), "Loading sandbox image")
    _check(_run(["kind", "load", "docker-image", sink_image, "--name", cluster], timeout=180), "Loading sink image")
    return sandbox_image, sink_image


def _apply_manifests(sink_image: str) -> None:
    root = _repo_root()
    for name in ("namespace.yaml", "sink.yaml", "network-policy.yaml"):
        _check(_run(["kubectl", "apply", "-f", str(root / "k8s" / name)], timeout=60), f"Applying {name}")
    _check(_run(["kubectl", "-n", "agentguard-sandbox", "set", "image",
                 "deployment/agentguard-sink", f"sink={sink_image}"], timeout=60), "Selecting sink image")
    _check(_run(["kubectl", "-n", "agentguard-sandbox", "rollout", "status",
                 "deployment/agentguard-sink", "--timeout=90s"], timeout=120), "Waiting for sink")
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


def _monitoring_tier() -> str:
    probe = _run(["kubectl", "-n", "kube-system", "get", "daemonset", "tetragon", "-o", "name"])
    return "tetragon" if probe.returncode == 0 and probe.stdout.strip() else "fallback"


def _start_tetragon_stream(since: datetime) -> subprocess.Popen[str] | None:
    if _monitoring_tier() != "tetragon":
        return None
    try:
        return subprocess.Popen(
            ["kubectl", "-n", "kube-system", "logs", "-l",
             "app.kubernetes.io/name=tetragon", "--all-containers=true",
             "--since-time", since.isoformat(), "--follow"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    except OSError:
        return None


def _event_matches_pod(value: object, pod: str, namespace: str = "agentguard-sandbox") -> bool:
    if isinstance(value, dict):
        if value.get("name") == pod and value.get("namespace") == namespace:
            return True
        return any(_event_matches_pod(item, pod, namespace) for item in value.values())
    if isinstance(value, list):
        return any(_event_matches_pod(item, pod, namespace) for item in value)
    return False


def _finish_tetragon_stream(process: subprocess.Popen[str] | None, pod: str) -> list[dict]:
    if process is None:
        return []
    try:
        process.terminate()
        stdout, _ = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, _ = process.communicate(timeout=5)
    events = []
    for line in stdout.splitlines():
        if not line.lstrip().startswith("{"):
            line = line[line.find("{"):] if "{" in line else ""
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and _event_matches_pod(event, pod):
            events.append({"type": "tetragon", "pod": pod, "event": event})
    return events


def _run_probe(pod: str, target: str, timeout: int = 20) -> tuple[bool, str]:
    result = _run(["kubectl", "-n", "agentguard-sandbox", "exec", pod, "--", "python", "-c", target], timeout=timeout)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def _create_pod(pod: str, image: str, scan_id: str) -> None:
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
    agentguard-scan: "true"
    scan-id: "{scan_id}"
spec:
  restartPolicy: Never
  activeDeadlineSeconds: 300
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: skill
    image: {image}
    imagePullPolicy: Never
    command: ["sleep", "3600"]
    env:
    - name: AGENTGUARD_SINK_URL
      value: http://agentguard-sink.agentguard-sandbox.svc.cluster.local:8080/collect/{scan_id}
    - name: AGENTGUARD_SCAN_TOKEN
      value: {scan_id}
{agent_env}    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      capabilities:
        drop: ["ALL"]
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
        ephemeral-storage: 64Mi
      limits:
        cpu: "1"
        memory: 512Mi
        ephemeral-storage: 512Mi
    volumeMounts:
    - name: tmp
      mountPath: /tmp
    - name: skill
      mountPath: /skill
    - name: honeypots
      mountPath: /honeypots
  volumes:
  - name: tmp
    emptyDir: {{}}
  - name: skill
    emptyDir: {{}}
  - name: honeypots
    emptyDir: {{}}
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


def _events_from_logs(since: datetime, scan_id: str) -> list[dict]:
    logs = _run([
        "kubectl", "-n", "agentguard-sandbox", "logs", "deployment/agentguard-sink",
        "--since-time", since.isoformat(),
    ], timeout=30)
    events = []
    for line in logs.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict) and event.get("scan_token") == scan_id:
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
    scan_id = uuid.uuid4().hex
    pod = f"agentguard-run-{scan_id[:8]}"
    sandbox_image, sink_image = _build_images(cluster)
    _apply_manifests(sink_image)
    scan_started = datetime.now(timezone.utc)
    tetragon_stream = _start_tetragon_stream(scan_started)
    try:
        _create_pod(pod, sandbox_image, scan_id)
        image_id = _run([
            "kubectl", "-n", namespace, "get", "pod", pod,
            "-o", "jsonpath={.status.containerStatuses[?(@.name=='skill')].imageID}",
        ], timeout=30)
        image_event = {
            "type": "sandbox_image",
            "tag": sandbox_image,
            "image_id": image_id.stdout.strip() if image_id.returncode == 0 else None,
        }
        _check(_run(["kubectl", "-n", namespace, "exec", pod, "--", "mkdir", "-p", "/skill", "/honeypots"], timeout=30), "Preparing sandbox")
        _copy_skill(root, pod)
        _check(_run(["kubectl", "-n", namespace, "exec", pod, "--", "sh", "-c",
                     f"printf 'agentguard-honeypot-{scan_id}\\n' > /honeypots/aws-credentials"], timeout=30), "Creating honeypot")
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
        dns_ok, dns_detail = _run_probe(
            pod,
            "import socket; socket.create_connection(('1.1.1.1', 53), 3)",
        )
        if dns_ok:
            raise DynamicUnavailable(
                "NetworkPolicy external DNS proof failed: sandbox reached a public DNS server. "
                f"Probe output: {dns_detail}"
            )
        prepare = _run(["kubectl", "-n", namespace, "exec", pod, "--", "python", "/opt/agentguard/run_skill.py", "--phase", "prepare"], timeout=60)
        if prepare.returncode:
            return DynamicResult("error", "fallback", events=[{"type": "prepare_error", "stderr": prepare.stderr}], error="Sandbox preparation failed")
        command = os.environ.get("AGENTGUARD_ENTRYPOINT", "")
        args = ["python", "/opt/agentguard/run_skill.py", "--phase", "execute"]
        if command:
            args.extend(["--command", command])
        execute = _run(["kubectl", "-n", namespace, "exec", pod, "--", *args], timeout=int(os.environ.get("AGENTGUARD_DYNAMIC_TIMEOUT", "120")))
        tetragon_events = _finish_tetragon_stream(tetragon_stream, pod)
        tetragon_stream = None
        events = [image_event]
        events.extend(_events_from_logs(scan_started, scan_id))
        events.extend(_events_from_pod(pod))
        events.extend(tetragon_events)
        trace = _run(["kubectl", "-n", namespace, "exec", pod, "--", "cat", "/tmp/agentguard-trace"], timeout=30)
        trace_text = trace.stdout
        if "/honeypots/aws-credentials" in trace_text and events:
            events.append({
                "type": "honeypot_exfiltration",
                "honeypot_hit": True,
                "path": "/honeypots/aws-credentials",
                "destination": "agentguard-sink",
                "scan_token": scan_id,
                "monitoring_tier": "tetragon" if tetragon_events else "fallback",
            })
        if execute.returncode:
            events.append({"type": "execution_error", "exit_code": execute.returncode, "stderr": execute.stderr[-2000:]})
        tier = "tetragon" if tetragon_events else "fallback"
        if _monitoring_tier() == "tetragon" and not tetragon_events:
            events.append({"type": "tetragon_unavailable", "pod": pod})
        return collect_events(events, monitoring_tier=tier)
    finally:
        if tetragon_stream is not None:
            _finish_tetragon_stream(tetragon_stream, pod)
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
