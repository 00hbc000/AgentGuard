from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class PolicyViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolPolicy:
    allowed_tools: frozenset[str] = frozenset({"read_file", "list_files", "run_python"})
    max_output_bytes: int = 16_384

    def validate(self, tool: str, arguments: dict[str, Any]) -> None:
        if tool not in self.allowed_tools:
            raise PolicyViolation(f"Tool is not allowlisted: {tool}")
        if tool in {"read_file", "run_python"}:
            path = arguments.get("path") if tool == "read_file" else arguments.get("script")
            if not isinstance(path, str) or not path.startswith("/skill/"):
                raise PolicyViolation(f"{tool} must stay under /skill")
        if tool == "list_files" and arguments.get("path", "/skill") not in {"/skill", "/tmp"}:
            raise PolicyViolation("list_files path is outside the allowlist")
