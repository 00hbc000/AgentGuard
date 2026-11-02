import yaml

import agentguard.dynamic.runner as runner
from agentguard.dynamic.runner import _event_matches_pod


def test_tetragon_event_is_correlated_by_nested_pod_name():
    event = {"process_exec": {"process": {"pod": {
        "name": "agentguard-run-ab12", "namespace": "agentguard-sandbox",
    }}}}
    assert _event_matches_pod(event, "agentguard-run-ab12")


def test_tetragon_event_for_another_pod_is_not_correlated():
    event = {"process_exec": {"process": {"pod": {"name": "other-pod"}}}}
    assert not _event_matches_pod(event, "agentguard-run-ab12")


def test_sandbox_pod_manifest_is_valid_yaml(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        if "input_text" in kwargs:
            captured["manifest"] = kwargs["input_text"]
        return runner.subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(runner, "_run", fake_run)
    monkeypatch.setattr(runner, "_check", lambda result, action: "")
    runner._create_pod("agentguard-run-ab12", "agentguard-sandbox:test", "scan-ab12")

    manifest = yaml.safe_load(captured["manifest"])
    container = manifest["spec"]["containers"][0]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["resources"]["limits"]["memory"] == "512Mi"
    assert len(container["volumeMounts"]) == 3
    assert len(manifest["spec"]["volumes"]) == 3
