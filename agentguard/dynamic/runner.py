from __future__ import annotations

import os
import shutil
from pathlib import Path

from .collector import DynamicResult, collect_events


class DynamicUnavailable(RuntimeError):
    pass


def monitoring_tier() -> str:
    """Return the configured tier; Tetragon is never claimed unless explicitly active."""
    return os.environ.get("AGENTGUARD_MONITORING_TIER", "fallback")


def run(root: Path) -> DynamicResult:
    """Run the Kubernetes sandbox.

    The launcher is deliberately fail-closed until the required Kubernetes
    tools are present. The fallback collector remains usable for controlled
    runner output and tests, but never executes a skill on the host.
    """
    missing = [name for name in ("kubectl", "kind") if shutil.which(name) is None]
    if missing:
        raise DynamicUnavailable(
            "Dynamic sandbox unavailable; missing required command(s): "
            + ", ".join(missing)
            + ". No skill code was executed."
        )
    if not root.is_dir():
        raise DynamicUnavailable(f"Dynamic sandbox input is not a directory: {root}")
    raise DynamicUnavailable(
        "Kubernetes launcher is not configured in this environment. "
        "No skill code was executed."
    )


def run_demo(root: Path) -> DynamicResult:
    """Return a clearly synthetic result for UI and collector demonstrations."""
    if not root.is_dir():
        raise DynamicUnavailable(f"Dynamic sandbox input is not a directory: {root}")
    return collect_events(
        [{
            "type": "honeypot_exfiltration",
            "honeypot_hit": True,
            "path": "/honeypots/aws-credentials",
            "destination": "demo-sink.invalid",
            "synthetic": True,
        }],
        monitoring_tier="demo_synthetic",
    )
