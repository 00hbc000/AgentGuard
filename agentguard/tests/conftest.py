"""Hermetic test environment.

Developers (and the Kali handoff) export AGENTGUARD_* variables such as AGENTGUARD_AGENT_MODE=ollama or
AGENTGUARD_CISCO_COMMAND in their shells. Those must never change what the unit tests exercise, so every
test starts from a clean AGENTGUARD_* environment and opts in explicitly via monkeypatch.
"""
import os

import pytest


@pytest.fixture(autouse=True)
def _clean_agentguard_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("AGENTGUARD_"):
            monkeypatch.delenv(name, raising=False)
    # scanner auto-detection must not pick up whatever happens to be installed on the dev machine
    monkeypatch.setenv("AGENTGUARD_DISABLE_SCANNER_DISCOVERY", "1")
    yield
