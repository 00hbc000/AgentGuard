from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

import urllib.request


def _emit(event: dict) -> None:
    with Path("/tmp/agentguard-agent-events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
    print(json.dumps(event, sort_keys=True), flush=True)


def _action(endpoint: str, model: str, prompt: str) -> tuple[str, dict, str]:
    payload = json.dumps({
        "model": model, "stream": False, "format": "json",
        "options": {"temperature": 0},
        "messages": [{"role": "system", "content": "Return JSON: tool, arguments, rationale. Tools: list_files, read_file, run_python, done."},
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
    return action["tool"], action.get("arguments", {}), str(action.get("rationale", ""))


def _tool(action: str, arguments: dict) -> tuple[int, str]:
    if action == "list_files":
        path = arguments.get("path", "/skill")
        result = subprocess.run(["find", path, "-maxdepth", "2", "-type", "f"], capture_output=True, text=True, timeout=10)
    elif action == "read_file":
        result = subprocess.run(["sed", "-n", "1,240p", arguments["path"]], capture_output=True, text=True, timeout=10)
    elif action == "run_python":
        result = subprocess.run(["python", arguments["script"]], cwd="/skill", capture_output=True, text=True, timeout=30)
    else:
        raise PolicyViolation(f"Unknown tool: {action}")
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
