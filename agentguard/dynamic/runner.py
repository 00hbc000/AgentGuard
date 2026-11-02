from __future__ import annotations

import hashlib
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
from typing import Callable

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


def _sandbox_sources() -> list[Path]:
    root = _repo_root() / "sandbox"
    files = [path for path in root.glob("*") if path.is_file()]
    files += [path for path in (root / "guard").glob("*") if path.is_file()]
    return sorted(files)


def image_tag() -> str:
    """Content hash of everything baked into the images, so unchanged code reuses images."""
    override = os.environ.get("AGENTGUARD_IMAGE_TAG")
    if override:
        return override
    digest = hashlib.sha256()
    root = _repo_root() / "sandbox"
    for path in _sandbox_sources():
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


def _image_in_docker(image: str) -> bool:
    return _run(["docker", "image", "inspect", image], timeout=30).returncode == 0


def _image_in_cluster(cluster: str, repository: str, tag: str) -> bool:
    result = _run(["docker", "exec", f"{cluster}-control-plane", "crictl", "images"], timeout=30)
    if result.returncode:
        return False
    return any(repository in line and tag in line.split() for line in result.stdout.splitlines())


def _build_images(cluster: str, progress: Callable[[str], None] | None = None) -> tuple[str, str]:
    """Build (only when missing) and load the sandbox and sink images into kind."""
    say = progress or (lambda message: None)
    root = _repo_root()
    tag = image_tag()
    sandbox_image = f"agentguard-sandbox:{tag}"
    sink_image = f"agentguard-sink:{tag}"
    build_args = ["--build-arg", f"AGENTGUARD_BUILD_TAG={tag}"]
    if not _image_in_docker(sandbox_image):
        say(f"Building sandbox image {tag} (first run only; later scans reuse it)")
        _check(_run(["docker", "build", *build_args, "-t", sandbox_image, str(root / "sandbox")], timeout=600),
               "Building sandbox image")
    if not _image_in_docker(sink_image):
        say(f"Building sink image {tag}")
        _check(_run(["docker", "build", "-f", str(root / "sandbox" / "Sink.Dockerfile"),
                     *build_args, "-t", sink_image, str(root / "sandbox")], timeout=600), "Building sink image")
    for repository, image in (("agentguard-sandbox", sandbox_image), ("agentguard-sink", sink_image)):
        if not _image_in_cluster(cluster, repository, tag):
            say(f"Loading {image} into kind cluster '{cluster}'")
            _check(_run(["kind", "load", "docker-image", image, "--name", cluster], timeout=300),
                   f"Loading {repository} image")
    return sandbox_image, sink_image


def prepare_images(progress: Callable[[str], None] | None = None) -> str:
    """Build and load images ahead of time (used by ``agentguard prepare-sandbox``)."""
    _require_tools()
    _build_images(os.environ.get("AGENTGUARD_KIND_CLUSTER", "agentguard"), progress)
    return image_tag()


def _preflight() -> None:
    nodes = _run(["kubectl", "get", "nodes", "-o", "name"], timeout=30)
    if nodes.returncode or not nodes.stdout.strip():
        detail = (nodes.stderr or nodes.stdout).strip()[:300]
        raise DynamicUnavailable(
            "kubectl cannot reach a Kubernetes cluster. Create one with `kind create cluster --name agentguard` "
            f"(see docs/KALI-QUICKSTART.md). Detail: {detail or 'no output'}. No skill code was executed."
        )


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
            if path.is_symlink() or ".git" in path.relative_to(root).parts:
                continue
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


def _events_from_logs(since: datetime, scan_id: str, pod_ip: str | None = None) -> list[dict]:
    """Sink events for this scan: matched by scan token, canary token, or the pod's source IP."""
    logs = _run([
        "kubectl", "-n", "agentguard-sandbox", "logs", "deployment/agentguard-sink",
        "--since-time", since.isoformat(), "--tail=-1",
    ], timeout=30)
    events = []
    for line in logs.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        canary_tokens = {hit.get("token") for hit in event.get("canary_hits") or [] if isinstance(hit, dict)}
        if (event.get("scan_token") == scan_id or scan_id in canary_tokens
                or (pod_ip and event.get("source") == pod_ip)):
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


def _sink_addresses(namespace: str) -> set[str]:
    """Hostnames/IPs of the controlled sink, so traffic to it is not reported as egress."""
    allowed = {"agentguard-sink", "agentguard-sink.agentguard-sandbox",
               "agentguard-sink.agentguard-sandbox.svc", "agentguard-sink.agentguard-sandbox.svc.cluster.local"}
    for command in (["kubectl", "-n", namespace, "get", "svc", "agentguard-sink", "-o", "jsonpath={.spec.clusterIP}"],
                    ["kubectl", "-n", namespace, "get", "pod", "-l", "agentguard.io/role=sink",
                     "-o", "jsonpath={.items[*].status.podIP}"]):
        result = _run(command, timeout=30)
        if result.returncode == 0:
            allowed.update(result.stdout.split())
    return allowed


def run(root: Path, progress: Callable[[str], None] | None = None) -> DynamicResult:
    """Run the skill in a kind Kubernetes pod with sink-only egress."""
    say = progress or (lambda message: None)
    _require_tools()
    say("Checking Kubernetes cluster")
    _preflight()
    cluster = os.environ.get("AGENTGUARD_KIND_CLUSTER", "agentguard")
    namespace = "agentguard-sandbox"
    scan_id = uuid.uuid4().hex
    pod = f"agentguard-run-{scan_id[:8]}"
    sandbox_image, sink_image = _build_images(cluster, say)
    say("Applying sandbox namespace, sink and NetworkPolicies")
    _apply_manifests(sink_image)
    allowed_hosts = _sink_addresses(namespace)
    scan_started = datetime.now(timezone.utc)
    tetragon_stream = _start_tetragon_stream(scan_started)
    try:
        say(f"Creating sandbox pod {pod}")
        _create_pod(pod, sandbox_image, scan_id)
        image_id = _run([
            "kubectl", "-n", namespace, "get", "pod", pod,
            "-o", "jsonpath={.status.containerStatuses[?(@.name=='skill')].imageID}",
        ], timeout=30)
        pod_ip = _run(["kubectl", "-n", namespace, "get", "pod", pod, "-o", "jsonpath={.status.podIP}"],
                      timeout=30).stdout.strip() or None
        image_event = {
            "type": "sandbox_image",
            "tag": sandbox_image,
            "image_id": image_id.stdout.strip() if image_id.returncode == 0 else None,
            "pod": pod,
            "pod_ip": pod_ip,
        }
        _check(_run(["kubectl", "-n", namespace, "exec", pod, "--", "mkdir", "-p", "/skill", "/honeypots"], timeout=30), "Preparing sandbox")
        say("Copying skill into the sandbox (read by the pod, never executed on the host)")
        _copy_skill(root, pod)
        say("Proving network isolation (public internet, sink allow-list, external DNS)")
        internet_ok, internet_detail = _run_probe(
            pod,
            "import socket; socket.create_connection(('1.1.1.1', 80), 3)",
        )
        if internet_ok:
            raise DynamicUnavailable(
                "NetworkPolicy isolation proof failed: sandbox reached the public internet. "
                f"Probe output: {internet_detail}. Your kind cluster needs a CNI that enforces NetworkPolicy "
                "(Calico). See docs/KALI-QUICKSTART.md."
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
        say("Planting honeypot credentials and canary environment variables")
        prepare = _run(["kubectl", "-n", namespace, "exec", pod, "--", "python", "/opt/agentguard/run_skill.py", "--phase", "prepare"], timeout=60)
        if prepare.returncode:
            return DynamicResult("error", "fallback", events=[{"type": "prepare_error", "stderr": prepare.stderr}],
                                 error="Sandbox preparation failed: " + (prepare.stderr or prepare.stdout).strip()[:500])
        command = os.environ.get("AGENTGUARD_ENTRYPOINT", "")
        args = ["python", "/opt/agentguard/run_skill.py", "--phase", "execute"]
        if command:
            args.extend(["--command", command])
        say("Executing the skill inside the sandbox")
        timed_out = False
        try:
            execute = _run(["kubectl", "-n", namespace, "exec", pod, "--", *args],
                           timeout=int(os.environ.get("AGENTGUARD_DYNAMIC_TIMEOUT", "240")))
        except DynamicUnavailable as exc:
            if "timed out" not in str(exc):
                raise
            # Keep whatever evidence the sink and pod captured before the timeout.
            timed_out = True
            execute = subprocess.CompletedProcess(args, 124, "", "Skill execution exceeded the time limit")
        say("Collecting sink, guard, strace and Tetragon evidence")
        tetragon_events = _finish_tetragon_stream(tetragon_stream, pod)
        tetragon_stream = None
        events = [image_event]
        events.extend(_events_from_logs(scan_started, scan_id, pod_ip))
        events.extend(_events_from_pod(pod))
        events.extend(tetragon_events)
        if execute.returncode:
            events.append({"type": "execution_error", "exit_code": execute.returncode, "timed_out": timed_out,
                           "stderr": execute.stderr[-2000:], "stdout": execute.stdout[-2000:]})
        tier = "tetragon" if tetragon_events else "fallback"
        if _monitoring_tier() == "tetragon" and not tetragon_events:
            events.append({"type": "tetragon_unavailable", "pod": pod})
        return collect_events(events, monitoring_tier=tier, scan_token=scan_id, allowed_hosts=allowed_hosts)
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
