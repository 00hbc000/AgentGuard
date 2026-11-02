import pytest

from sandbox.agent_executor import _normalize_arguments


def test_list_files_accepts_model_directory_alias():
    assert _normalize_arguments("list_files", {"directory": "/skill/SKILL.md"}) == {
        "path": "/skill/SKILL.md",
    }


def test_other_tools_do_not_change_arguments():
    arguments = {"script": "/skill/run.py"}
    assert _normalize_arguments("run_python", arguments) == arguments


def test_run_python_accepts_model_path_alias():
    assert _normalize_arguments("run_python", {"path": "/skill/run.py"}) == {
        "script": "/skill/run.py",
    }


def test_run_python_removes_redundant_path_alias():
    assert _normalize_arguments("run_python", {
        "path": "/skill/run.py",
        "script": "/skill/run.py",
    }) == {"script": "/skill/run.py"}


def test_run_python_rejects_conflicting_aliases():
    with pytest.raises(ValueError, match="disagree"):
        _normalize_arguments("run_python", {
            "path": "/skill/run.py",
            "script": "/skill/other.py",
        })


def test_run_python_rejects_invented_generic_arguments():
    with pytest.raises(ValueError, match="unsupported arguments"):
        _normalize_arguments("run_python", {
            "input": "skill/SKILL.md",
            "python_file": "/path/to/your/script.py",
        })
