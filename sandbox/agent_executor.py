from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

import urllib.request


_MAX_PATH_LENGTH = 4096
_MAX_FILE_BYTES = 64 * 1024
_MAX_ERROR_ARGUMENT_BYTES = 2048
_SKILL_ROOT = Path("/skill").resolve()


def _skill_path(value: object, key: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_PATH_LENGTH or "\x00" in value:
        raise ValueError(f"{key} must be a non-empty path")
    candidate = Path(value).resolve(strict=True)
    if candidate != _SKILL_ROOT and _SKILL_ROOT not in candidate.parents:
        raise ValueError(f"{key} must stay under /skill")
    return str(candidate)


def _normalize_arguments(action: str, arguments: dict) -> dict:
    normalized = dict(arguments)
    if action == "list_files" and "path" not in normalized and "directory" in normalized:
        normalized["path"] = normalized.pop("directory")
    if action == "run_python" and "path" in normalized:
        path = normalized.pop("path")
        if "script" in normalized and normalized["script"] != path:
            raise ValueError("run_python path and script arguments disagree")
        normalized.setdefault("script", path)
    allowed = {
        "list_files": {"path"},
        "read_file": {"path"},
        "run_python": {"script"},
        "done": set(),
    }.get(action)
    if allowed is None or set(normalized) - allowed:
        raise ValueError(f"Unknown or unsupported arguments for tool: {action}")
    return normalized


def _validate_arguments(action: str, arguments: dict) -> dict:
    validated = dict(arguments)
    if action == "list_files":
        validated["path"] = _skill_path(validated.get("path", "/skill"), "path")
    elif action == "read_file":
        validated["path"] = _skill_path(validated.get("path"), "path")
    elif action == "run_python":
        validated["script"] = _skill_path(validated.get("script"), "script")
    return validated


def _emit(event: dict) -> None:
    with Path("/tmp/agentguard-agent-events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
    print(json.dumps(event, sort_keys=True), flush=True)


def _action(endpoint: str, model: str, prompt: str) -> tuple[str, dict, str]:
    tool_schema = (
        "Return exactly one JSON object with string field tool, object field arguments, "
        "and optional string field rationale. Use only these exact tool schemas: "
        "list_files arguments {\"path\": \"/skill\"} (directory is also accepted); "
        "read_file arguments {\"path\": \"/skill/FILE\"}; "
        "run_python arguments {\"script\": \"/skill/FILE.py\"}; "
        "done arguments {}. "
        "Do not use python_file, input, code, command, directory for run_python, or placeholder paths. "
        "Only choose run_python when the skill contains a real Python file."
    )
    payload = json.dumps({
        "model": model, "stream": False, "format": "json",
        "options": {"temperature": 0},
        "messages": [{"role": "system", "content": tool_schema},
                     {"role": "user", "content": prompt}],
    }).encode()
    request = urllib.request.Request(endpoint.rstrip("/") + "/api/chat", data=payload,
                                     headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.loads(response.read().decode())
    content = body["message"]["content"]
    action = json.loads(content)
    if not isinstance(action, dict) or not isinstance(action.get("tool"), str) or not isinstance(action.get("arguments", {}), dict):
        raise ValueError("invalid Ollama action")
    tool = action["tool"]
    raw_arguments = action.get("arguments", {})
    try:
        normalized_arguments = _normalize_arguments(tool, raw_arguments)
    except ValueError as exc:
        details = json.dumps(raw_arguments, sort_keys=True, separators=(",", ":"))
        raise ValueError(
            f"{exc}; raw_arguments={details[:_MAX_ERROR_ARGUMENT_BYTES]}"
        ) from exc
    return tool, normalized_arguments, str(action.get("rationale", ""))


def _tool(action: str, arguments: dict) -> tuple[int, str]:
    if action == "list_files":
        path = arguments.get("path", "/skill")
        result = subprocess.run(["find", path, "-maxdepth", "2", "-type", "f"], capture_output=True, text=True, timeout=10)
    elif action == "read_file":
        if Path(arguments["path"]).stat().st_size > _MAX_FILE_BYTES:
            raise ValueError("read_file target exceeds the size limit")
        result = subprocess.run(["sed", "-n", "1,240p", arguments["path"]], capture_output=True, text=True, timeout=10)
    elif action == "run_python":
        result = subprocess.run(["python", arguments["script"]], cwd="/skill", capture_output=True, text=True, timeout=30)
    else:
        raise ValueError(f"Unknown tool: {action}")
    output = (result.stdout + result.stderr)[:16_384]
    return result.returncode, output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-turns", type=int, default=8)
    args = parser.parse_args()
    endpoint = os.environ.get("AGENTGUARD_OLLAMA_URL")
    model = os.environ.get("AGENTGUARD_OLLAMA_MODEL", "qwen2.5:7b")
    if not endpoint:
        _emit({"type": "agent_error", "error": "AGENTGUARD_OLLAMA_URL is required"})
        return 2
    allowed = {"list_files", "read_file", "run_python", "done"}
    context = "Read /skill/SKILL.md and complete its instructions. Start by inspecting files. Do not invent credentials."
    for turn in range(args.max_turns):
        started = time.monotonic()
        try:
            tool, arguments, rationale = _action(endpoint, model, context)
            if tool not in allowed:
                raise ValueError(f"tool is not allowlisted: {tool}")
            arguments = _validate_arguments(tool, arguments)
            if tool == "done":
                _emit({"type": "agent_action", "turn": turn + 1, "tool": tool, "arguments": arguments, "rationale": rationale})
                return 0
            if tool == "read_file" and not str(arguments.get("path", "")).startswith("/skill/"):
                raise ValueError("read_file must stay under /skill")
            if tool == "run_python" and not str(arguments.get("script", "")).startswith("/skill/"):
                raise ValueError("run_python must stay under /skill")
            code, output = _tool(tool, arguments)
            _emit({"type": "agent_action", "turn": turn + 1, "tool": tool,
                   "arguments": arguments, "rationale": rationale,
                   "exit_code": code, "output": output})
            context = f"Previous tool output:\n{output}\nChoose the next allowlisted action or return tool=done."
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            _emit({"type": "agent_error", "turn": turn + 1, "error": str(exc)})
            return 2
        if time.monotonic() - started > 60:
            _emit({"type": "agent_error", "turn": turn + 1, "error": "action exceeded time limit"})
            return 2
    _emit({"type": "agent_limit", "max_turns": args.max_turns})
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
