from sandbox.agent_executor import _normalize_arguments


def test_list_files_accepts_model_directory_alias():
    assert _normalize_arguments("list_files", {"directory": "/skill/SKILL.md"}) == {
        "path": "/skill/SKILL.md",
    }


def test_other_tools_do_not_change_arguments():
    arguments = {"script": "/skill/run.py"}
    assert _normalize_arguments("run_python", arguments) == arguments
