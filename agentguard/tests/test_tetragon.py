from agentguard.dynamic.runner import _event_contains_pod


def test_tetragon_event_is_correlated_by_nested_pod_name():
    event = {"process_exec": {"process": {"pod": {"name": "agentguard-run-ab12"}}}}
    assert _event_contains_pod(event, "agentguard-run-ab12")


def test_tetragon_event_for_another_pod_is_not_correlated():
    event = {"process_exec": {"process": {"pod": {"name": "other-pod"}}}}
    assert not _event_contains_pod(event, "agentguard-run-ab12")
