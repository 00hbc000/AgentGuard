"""Locate the optional external scanners (Cisco skill-scanner, NVIDIA SkillSpector).

Lookup order for each scanner:
  1. AGENTGUARD_CISCO_COMMAND / AGENTGUARD_NVIDIA_COMMAND   (explicit, e.g. "/opt/x/bin/skill-scanner scan")
  2. <repo>/.venvs/<name>/bin/<exe>
  3. ~/.venvs/<name>/bin/<exe>   (name: cisco | cisco-skill-scanner | skillspector; install_scanners.sh creates these)
  4. <exe> on PATH

A missing scanner is reported as ``skipped`` (never an error), so a native scan keeps working.
Set AGENTGUARD_DISABLE_SCANNER_DISCOVERY=1 to use only the explicit environment variables.
"""
from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path

SCANNERS = {
    "cisco": {"env": "AGENTGUARD_CISCO_COMMAND", "venv": ("cisco", "cisco-skill-scanner"), "exe": "skill-scanner", "args": ["scan"]},
    "nvidia": {"env": "AGENTGUARD_NVIDIA_COMMAND", "venv": ("skillspector",), "exe": "skillspector", "args": ["scan"]},
}
REPO_ROOT = Path(__file__).resolve().parents[1]


def _venv_roots() -> list[Path]:
    return [REPO_ROOT / ".venvs", Path(os.environ.get("AGENTGUARD_VENV_DIR", Path.home() / ".venvs"))]


def locate(tool: str) -> tuple[list[str] | None, str]:
    """Return (command, source). ``command`` is None when the scanner cannot be found."""
    spec = SCANNERS[tool]
    explicit = os.environ.get(spec["env"], "").strip()
    if explicit:
        return shlex.split(explicit), f"env {spec['env']}"
    if os.environ.get("AGENTGUARD_DISABLE_SCANNER_DISCOVERY"):
        return None, "not configured"
    for root in _venv_roots():
        for name in spec["venv"]:
            candidate = root / name / "bin" / spec["exe"]
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return [str(candidate), *spec["args"]], f"venv {candidate.parent.parent}"
    found = shutil.which(spec["exe"])
    if found:
        return [found, *spec["args"]], "PATH"
    return None, "not installed (run scripts/install_scanners.sh)"


def status() -> dict[str, dict[str, object]]:
    """Health summary for the dashboard / CLI."""
    result: dict[str, dict[str, object]] = {}
    for tool in SCANNERS:
        command, source = locate(tool)
        ok = command is not None and (shutil.which(command[0]) is not None or Path(command[0]).is_file())
        result[tool] = {"available": bool(ok), "command": command, "source": source}
    return result
