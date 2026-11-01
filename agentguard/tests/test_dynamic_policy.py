import pytest

from agentguard.dynamic.policy import PolicyViolation, ToolPolicy


def test_policy_allows_skill_scoped_tools():
    policy = ToolPolicy()
    policy.validate("read_file", {"path": "/skill/SKILL.md"})
    policy.validate("run_python", {"script": "/skill/run.py"})


def test_policy_rejects_escape_and_unknown_tools():
    policy = ToolPolicy()
    with pytest.raises(PolicyViolation):
        policy.validate("read_file", {"path": "/etc/passwd"})
    with pytest.raises(PolicyViolation):
        policy.validate("shell", {"command": "id"})
