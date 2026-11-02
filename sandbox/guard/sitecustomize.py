"""AgentGuard in-pod runtime guard (Python audit hook).

Loaded automatically by every ``python`` process the sandbox starts, because
``PYTHONPATH`` points at this directory. It records - but never blocks - the
behaviours that matter for skill triage: reads of honeypot files, DNS lookups,
connection attempts, HTTP requests and payloads (with canary detection),
process spawns and dynamically compiled code. Events are appended as JSON lines
to ``AGENTGUARD_EVENTS_FILE`` (default ``/tmp/agentguard-agent-events.jsonl``).

Blocking is the NetworkPolicy's job; this hook supplies evidence for traffic
that the policy drops, which the sink can never see.

Limits: a skill that is not written in Python (or that runs ``python -I -S``)
bypasses the hook. The strace tracer and Tetragon cover those cases.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

_EVENTS = os.environ.get("AGENTGUARD_EVENTS_FILE", "/tmp/agentguard-agent-events.jsonl")
_HONEYPOT_DIR = os.environ.get("AGENTGUARD_HONEYPOT_DIR", "/honeypots")
_SENSITIVE = re.compile(r"(?:\.ssh|\.aws|\.git-credentials|\.netrc|\.npmrc|\.config/gh|/etc/shadow|/proc/[^/]+/environ)")
_CANARY = re.compile(r"AGCANARY-([0-9a-f]{32})-([A-Z0-9_]{2,40})")
_MAX_EVENTS = 400
_SKILL_DIR = os.environ.get("AGENTGUARD_SKILL_DIR", "/skill")
_count = 0
_seen: set[tuple] = set()
_busy = False

# Import before the audit hook is installed so the hook never triggers imports.
_canary_module = None
try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        import canary as _canary_module  # type: ignore
    finally:
        sys.path.pop(0)
except Exception:  # pragma: no cover - fall back to the plain regex below
    _canary_module = None


def _canaries(data) -> list[dict]:
    try:
        if _canary_module is not None:
            return _canary_module.find_canaries(data)
        raise RuntimeError("canary module unavailable")
    except Exception:  # pragma: no cover - guard must never break the skill
        text = data.decode("utf-8", "replace") if isinstance(data, (bytes, bytearray)) else str(data)
        return [{"token": m.group(1), "name": m.group(2), "encoding": "plain"} for m in _CANARY.finditer(text)]


def _emit(event: dict, dedupe: tuple | None = None) -> None:
    global _count, _busy
    if _busy or _count >= _MAX_EVENTS:
        return
    if dedupe is not None:
        if dedupe in _seen:
            return
        _seen.add(dedupe)
    _busy = True
    try:
        event.setdefault("source", "python_audit")
        event["ts"] = round(time.time(), 3)
        event["pid"] = os.getpid()
        with open(_EVENTS, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True, default=str) + "\n")
        _count += 1
    except Exception:
        pass
    finally:
        _busy = False


def _host_from_http_bytes(data: bytes) -> str | None:
    match = re.search(rb"\r\nHost:\s*([^\r\n]+)", data[:4096], re.I)
    return match.group(1).decode("latin-1").strip() if match else None


def _hook(event: str, args: tuple) -> None:
    try:
        if event == "open":
            path = args[0]
            if isinstance(path, bytes):
                path = os.fsdecode(path)
            if not isinstance(path, str):
                return
            if path == _EVENTS or path.startswith("/tmp/agentguard"):
                return
            if path.startswith(_HONEYPOT_DIR.rstrip("/") + "/") or _SENSITIVE.search(path):
                mode = args[1] if len(args) > 1 else None
                _emit({"type": "honeypot_read" if path.startswith(_HONEYPOT_DIR) else "sensitive_read",
                       "path": path, "mode": str(mode)}, dedupe=("open", path))
        elif event == "socket.getaddrinfo":
            host = args[0]
            if isinstance(host, bytes):
                host = host.decode("idna", "replace")
            _emit({"type": "dns_lookup", "host": str(host), "port": args[1]}, dedupe=("dns", str(host)))
        elif event == "socket.connect":
            address = args[1]
            _emit({"type": "network_attempt", "address": list(address) if isinstance(address, tuple) else str(address)},
                  dedupe=("connect", str(address)))
        elif event == "urllib.Request":
            url, data, _headers, method = args[0], args[1], args[2], args[3]
            hits = _canaries(data) if data else []
            _emit({"type": "http_request", "url": str(url)[:500], "method": method or ("POST" if data else "GET"),
                   "body_bytes": len(data) if data else 0, "canary_hits": hits},
                  dedupe=("urllib", str(url), bool(hits)))
        elif event == "http.client.send":
            data = args[1]
            if isinstance(data, (bytes, bytearray)):
                payload = bytes(data)
            else:
                return
            hits = _canaries(payload)
            if hits:
                _emit({"type": "network_payload", "host": _host_from_http_bytes(payload),
                       "bytes": len(payload), "canary_hits": hits},
                      dedupe=("payload", tuple(sorted(h["name"] for h in hits))))
        elif event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
            _emit({"type": "process_spawn", "api": event, "args": [str(a)[:200] for a in args[:3]]},
                  dedupe=("spawn", event, str(args[:2])))
        elif event == "exec":
            code = args[0]
            filename = getattr(code, "co_filename", "")
            if filename.startswith("<"):
                # Library helpers (dataclasses, namedtuple) also exec "<string>" code, so
                # only report exec() called directly from skill code or nested dynamic code.
                caller = sys._getframe(1).f_code.co_filename if hasattr(sys, "_getframe") else ""
                if caller.startswith(_SKILL_DIR) or caller == "<string>":
                    _emit({"type": "dynamic_exec", "filename": filename, "caller": caller},
                          dedupe=("exec", filename, caller))
    except Exception:
        # The guard must never crash or alter the behaviour of the skill.
        pass


if os.environ.get("AGENTGUARD_GUARD", "1") == "1":
    sys.addaudithook(_hook)
