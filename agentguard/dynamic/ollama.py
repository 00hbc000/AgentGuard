from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class OllamaError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentAction:
    tool: str
    arguments: dict[str, Any]
    rationale: str = ""


def _json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OllamaError("Ollama response was not a JSON object")
    return value


def request_action(endpoint: str, model: str, prompt: str, timeout: int = 60) -> AgentAction:
    payload = json.dumps({
        "model": model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
        "messages": [{
            "role": "system",
            "content": (
                "You are a sandboxed skill executor. Return only JSON with keys "
                "tool, arguments, rationale. Use only the requested allowlisted tool."
            ),
        }, {"role": "user", "content": prompt}],
    }).encode("utf-8")
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/api/chat",
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise OllamaError(f"Ollama request failed: {exc}") from exc
    message = _json_object(body.get("message"))
    content = message.get("content")
    if not isinstance(content, str):
        raise OllamaError("Ollama response did not contain message content")
    try:
        action = _json_object(json.loads(content))
    except json.JSONDecodeError as exc:
        raise OllamaError(f"Ollama returned non-JSON action: {exc}") from exc
    tool = action.get("tool")
    arguments = action.get("arguments", {})
    if not isinstance(tool, str) or not isinstance(arguments, dict):
        raise OllamaError("Ollama action must contain string tool and object arguments")
    return AgentAction(tool=tool, arguments=arguments, rationale=str(action.get("rationale", "")))
