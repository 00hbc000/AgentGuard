from __future__ import annotations

import json
import os
import urllib.request
from typing import Any


class AgentLoopError(RuntimeError):
    pass


def request_next_action(prompt: str, *, model: str = "claude-3-5-haiku-latest") -> dict[str, Any]:
    """Request one host-side sandbox action from Anthropic.

    The API key stays on the host and is never passed into the sandbox pod.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise AgentLoopError("ANTHROPIC_API_KEY is required for the sandbox agent loop")
    payload = json.dumps({
        "model": model,
        "max_tokens": 512,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    request = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentLoopError(f"Anthropic sandbox request failed: {exc}") from exc
    return body
