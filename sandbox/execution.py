"""In-pod execution harness for AgentGuard dynamic analysis.

This module only ever runs *inside* the sandbox pod (or inside unit tests with
the path overrides below). It:

1. plants honeypot decoys (fake ~/.aws, ~/.ssh, ... plus canary env vars),
2. discovers how the skill is meant to be run (``SKILL.md`` usage blocks,
   then ``scripts/*.py|sh``), substituting harmless sample files for placeholders,
3. runs each command under ``strace`` with the Python audit guard enabled,
4. writes structured JSON-line events that the host collects with
   ``kubectl exec ... cat``.

Paths can be overridden with ``AGENTGUARD_SKILL_DIR``, ``AGENTGUARD_HONEYPOT_DIR``
and ``AGENTGUARD_TMP_DIR`` so the harness can be unit-tested outside a pod. Inside
the pod the Pod manifest controls the environment, never the skill.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

try:  # imported as a package (tests) or as a script (inside the pod)
    from . import canary
except ImportError:  # pragma: no cover - exercised inside the pod
    import canary  # type: ignore

SKILL_DIR = Path(os.environ.get("AGENTGUARD_SKILL_DIR", "/skill"))
HONEYPOT_DIR = Path(os.environ.get("AGENTGUARD_HONEYPOT_DIR", "/honeypots"))
TMP_DIR = Path(os.environ.get("AGENTGUARD_TMP_DIR", "/tmp"))
EVENTS_FILE = TMP_DIR / "agentguard-agent-events.jsonl"
TRACE_FILE = TMP_DIR / "agentguard-trace"
GUARD_DIR = Path(__file__).resolve().parent / "guard"
MAX_COMMANDS = 8
OUTPUT_LIMIT = 4000

_PLACEHOLDER = re.compile(
    r"(?i)(?:path/to|/path/|<[^>]+>|\[[^\]]+\]|\{[^}]+\}|\byour[_-]|\bexample\b|\bfile\b|\binput\b|\boutput\b|"
    r"\$\{?\w+|\bFILE\b|\bPATH\b|\.\.\.)"
)
_SAMPLES = {
    ".csv": "id,name,score\n1,alice,90\n2,bob,85\n3,carol,77\n",
    ".txt": "hello world.this is a sample text file.   it has  odd spacing\n",
    ".json": '{"name": "sample", "items": [1, 2, 3]}\n',
    ".md": "# Sample\n\nSome markdown text.\n",
    ".log": "2026-01-01 INFO started\n2026-01-01 WARN something\n",
    ".html": "<html><body><p>sample</p></body></html>\n",
    ".xml": "<root><item>1</item></root>\n",
    ".yaml": "name: sample\nitems: [1, 2]\n",
}
_INTERPRETERS = {"python": "python", "python3": "python", "bash": "bash", "sh": "bash"}


def emit(event: dict) -> None:
    event.setdefault("ts", round(time.time(), 3))
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with EVENTS_FILE.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True, default=str) + "\n")


# --------------------------------------------------------------------------- honeypots
def home_dir() -> Path:
    return HONEYPOT_DIR / "home"


def create_honeypots(token: str) -> list[str]:
    """Create decoy credential files whose contents embed the scan canary."""
    values = canary.canary_env(token)
    home = home_dir()
    files = {
        home / ".aws" / "credentials": (
            "[default]\n"
            f"aws_access_key_id = {values['AWS_ACCESS_KEY_ID']}\n"
            f"aws_secret_access_key = {values['AWS_SECRET_ACCESS_KEY']}\n"
        ),
        home / ".ssh" / "id_rsa": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{canary.canary_value(token, 'SSH_PRIVATE_KEY')}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
        home / ".config" / "gh" / "hosts.yml": (
            "github.com:\n  user: octocat\n"
            f"  oauth_token: {values['GITHUB_TOKEN']}\n"
        ),
        home / ".npmrc": f"//registry.npmjs.org/:_authToken={values['NPM_TOKEN']}\n",
        home / ".git-credentials": f"https://octocat:{values['GITHUB_TOKEN']}@github.com\n",
        home / ".env": "".join(f"{key}={value}\n" for key, value in values.items()),
        # Legacy location used by earlier AgentGuard examples.
        HONEYPOT_DIR / "aws-credentials": f"{values['AWS_SECRET_ACCESS_KEY']}\n",
    }
    created = []
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        created.append(str(path))
    return created


def skill_env(token: str) -> dict[str, str]:
    """Environment for the skill process: decoy HOME, canary secrets, runtime guard."""
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("AGENTGUARD_OLLAMA") and key != "AGENTGUARD_AGENT_MODE"}
    env.update(canary.canary_env(token))
    env.update({
        "HOME": str(home_dir()),
        "PYTHONPATH": str(GUARD_DIR),
        "PYTHONDONTWRITEBYTECODE": "1",
        "AGENTGUARD_EVENTS_FILE": str(EVENTS_FILE),
        "AGENTGUARD_HONEYPOT_DIR": str(HONEYPOT_DIR),
        "AGENTGUARD_SKILL_DIR": str(SKILL_DIR),
        "AGENTGUARD_GUARD": "1",
        "TMPDIR": str(TMP_DIR),
    })
    return env


# --------------------------------------------------------------------------- discovery
def make_samples() -> dict[str, str]:
    directory = TMP_DIR / "samples"
    directory.mkdir(parents=True, exist_ok=True)
    result = {}
    for suffix, content in _SAMPLES.items():
        path = directory / f"sample{suffix}"
        path.write_text(content, encoding="utf-8")
        result[suffix] = str(path)
    return result


def _sample_for(arg: str, samples: dict[str, str]) -> str:
    suffix = Path(arg.split("?")[0]).suffix.lower()
    return samples.get(suffix, samples[".txt"])


def _substitute_args(args: list[str], samples: dict[str, str], skill_dir: Path) -> list[str]:
    result = []
    for arg in args:
        if arg.startswith("-") and "=" not in arg:
            result.append(arg)
        elif "=" in arg and arg.startswith("-"):
            flag, value = arg.split("=", 1)
            result.append(f"{flag}={_sample_for(value, samples)}" if _PLACEHOLDER.search(value) else arg)
        elif re.fullmatch(r"-?\d+(?:\.\d+)?", arg):
            result.append(arg)
        elif (skill_dir / arg).exists():
            result.append(arg)
        elif _PLACEHOLDER.search(arg) or Path(arg).suffix.lower() in samples:
            result.append(_sample_for(arg, samples))
        else:
            result.append(arg)
    return result


def _command_candidates(text: str) -> list[str]:
    candidates = []
    in_fence = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            candidates.append(stripped.lstrip("$ ").strip())
        for inline in re.findall(r"`([^`\n]+)`", line):
            candidates.append(inline.strip())
    return [item for item in candidates if re.match(r"(?:python3?|bash|sh)\s+\S", item)]


def discover_commands(skill_dir: Path | None = None, samples: dict[str, str] | None = None) -> list[dict]:
    """Return runnable commands: usage lines from docs first, then script fallbacks."""
    skill_dir = skill_dir or SKILL_DIR
    samples = samples or make_samples()
    commands: list[dict] = []
    seen: set[tuple[str, ...]] = set()

    def add(argv: list[str], origin: str) -> None:
        key = tuple(argv)
        if key in seen or len(commands) >= MAX_COMMANDS:
            return
        seen.add(key)
        commands.append({"argv": argv, "origin": origin})

    docs = [path for path in (skill_dir / "SKILL.md", skill_dir / "README.md") if path.is_file()]
    for doc in docs:
        try:
            text = doc.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for candidate in _command_candidates(text):
            candidate = re.split(r"\s(?:\||>|>>|&&|;|#)\s?", candidate, maxsplit=1)[0]
            try:
                tokens = shlex.split(candidate)
            except ValueError:
                continue
            if len(tokens) < 2 or tokens[0] not in _INTERPRETERS or tokens[1].startswith("-"):
                continue
            script = (skill_dir / tokens[1]).resolve()
            try:
                inside = skill_dir.resolve() in script.parents
            except OSError:
                inside = False
            if not (inside and script.is_file()):
                continue
            add([_INTERPRETERS[tokens[0]], str(script),
                 *_substitute_args(tokens[2:], samples, skill_dir)], doc.name)
    if len(commands) < MAX_COMMANDS:
        scripts = sorted(
            (path for path in skill_dir.rglob("*") if path.is_file()
             and path.suffix.lower() in {".py", ".sh"}
             and "__pycache__" not in path.parts and ".git" not in path.parts
             and path.name not in {"__init__.py", "setup.py", "conftest.py"}
             and not path.name.startswith("test_")),
            key=lambda p: (len(p.relative_to(skill_dir).parts), str(p)),
        )
        for path in scripts:
            interpreter = "python" if path.suffix.lower() == ".py" else "bash"
            if any(len(c["argv"]) > 1 and c["argv"][1] == str(path.resolve()) for c in commands):
                continue
            add([interpreter, str(path.resolve())], "script-discovery")
    return commands


# --------------------------------------------------------------------------- tracing
def strace_available() -> bool:
    exe = shutil.which("strace")
    if not exe:
        return False
    probe = subprocess.run([exe, "-o", os.devnull, "-e", "trace=none", "true"],
                           capture_output=True, timeout=10, check=False)
    return probe.returncode == 0


_OPENAT = re.compile(r'openat\([^,]+,\s*"([^"]+)"[^)]*\)\s*=\s*(-?\d+)')
_CONNECT_V4 = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)\}[^)]*\)\s*=\s*(-?\d+(?: \w+)?)')
_CONNECT_V6 = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\),.*?inet_pton\(AF_INET6,\s*"([^"]+)"\)[^}]*\},[^)]*\)\s*=\s*(-?\d+(?: \w+)?)')


def parse_strace(text: str, honeypot_dir: Path | None = None) -> list[dict]:
    """Extract honeypot opens and non-loopback connections from an strace log."""
    honeypot = str((honeypot_dir or HONEYPOT_DIR)).rstrip("/") + "/"
    events: list[dict] = []
    seen: set[tuple] = set()
    for line in text.splitlines():
        match = _OPENAT.search(line)
        if match and match.group(1).startswith(honeypot) and int(match.group(2)) >= 0:
            key = ("open", match.group(1))
            if key not in seen:
                seen.add(key)
                events.append({"type": "honeypot_read", "source": "strace", "path": match.group(1)})
            continue
        connect = _CONNECT_V4.search(line) or _CONNECT_V6.search(line)
        if connect:
            port, address = int(connect.group(1)), connect.group(2)
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_unspecified:
                continue
            key = ("connect", address, port)
            if key not in seen:
                seen.add(key)
                events.append({"type": "network_attempt", "source": "strace", "address": [address, port],
                               "external": bool(ip.is_global), "result": connect.group(3)})
    return events


# --------------------------------------------------------------------------- running
def _tail(text: str, limit: int = OUTPUT_LIMIT) -> str:
    return text if len(text) <= limit else "...[truncated]...\n" + text[-limit:]


def run_command(argv: list[str], env: dict[str, str], *, timeout: int, trace: bool) -> dict:
    wrapped = list(argv)
    if trace:
        wrapped = ["strace", "-f", "-A", "-s", "128", "-e", "trace=openat,connect", "-o", str(TRACE_FILE), *argv]
    started = time.monotonic()
    timed_out = False
    try:
        process = subprocess.Popen(wrapped, cwd=str(SKILL_DIR), env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, errors="replace",
                                   start_new_session=True)
    except OSError as exc:
        return {"exit_code": None, "timed_out": False, "stdout": "", "stderr": str(exc),
                "duration_ms": 0, "launch_error": True}
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        stdout, stderr = process.communicate()
    return {"exit_code": process.returncode, "timed_out": timed_out, "stdout": stdout or "",
            "stderr": stderr or "", "duration_ms": round((time.monotonic() - started) * 1000)}


def execute(token: str, *, command: str = "", timeout: int = 30) -> int:
    """Run the skill's entrypoints and emit events. Returns 0 unless the harness itself fails."""
    if not SKILL_DIR.is_dir():
        emit({"type": "execution_error", "error": f"skill directory missing: {SKILL_DIR}"})
        return 2
    samples = make_samples()
    env = skill_env(token)
    if command:
        tokens = shlex.split(command)
        commands = [{"argv": tokens, "origin": "configured-entrypoint"}]
    else:
        commands = discover_commands(SKILL_DIR, samples)
    trace_ok = strace_available()
    emit({"type": "execution_plan", "trace_available": trace_ok, "commands": commands,
          "guard": (GUARD_DIR / "sitecustomize.py").is_file(),
          "honeypots": [str(p) for p in sorted(HONEYPOT_DIR.rglob("*")) if p.is_file()]})
    if not commands:
        emit({"type": "no_entrypoint",
              "detail": "No runnable python/bash entrypoint was found in SKILL.md or scripts/. "
                        "Nothing was executed; a prompt-only skill has no runtime behaviour to observe."})
        return 0
    TRACE_FILE.write_text("", encoding="utf-8")
    for item in commands:
        result = run_command(item["argv"], env, timeout=timeout, trace=trace_ok)
        output = (result["stdout"] or "") + "\n" + (result["stderr"] or "")
        hits = canary.find_canaries(output)
        emit({"type": "skill_command", "command": item["argv"], "origin": item["origin"],
              "exit_code": result["exit_code"], "timed_out": result["timed_out"],
              "duration_ms": result["duration_ms"], "stdout": _tail(result["stdout"]),
              "stderr": _tail(result["stderr"]), "canary_in_output": hits})
    if trace_ok:
        try:
            for event in parse_strace(TRACE_FILE.read_text(encoding="utf-8", errors="replace")):
                emit(event)
        except OSError:
            pass
    return 0
