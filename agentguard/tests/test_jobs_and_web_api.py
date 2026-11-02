import json
import os
import stat
import threading
import time
import urllib.error
import urllib.request

import pytest

from agentguard import samples
from agentguard.jobs import JobStore, outcome_for, validate_public_git_url
from agentguard.web import make_server


def wait_for(predicate, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.2)
    raise AssertionError("timed out")


def finished(store, job_id):
    return wait_for(lambda: (lambda m: m if m["status"] in {"complete", "partial", "failed", "cancelled", "interrupted"} else None)(store.get(job_id)))


@pytest.fixture()
def store(tmp_path):
    return JobStore(tmp_path / "data")


def test_quick_scan_job_is_durable_and_reports_verdict(store, tmp_path):
    source = samples.resolve_source("runtime-exfil-sink")
    job_id = store.submit(source, "quick", sample_id="runtime-exfil-sink")
    meta = finished(store, job_id)
    assert meta["status"] == "complete" and meta["verdict"] == "high_risk" and meta["outcome"] == "detected"
    assert [p["stage"] for p in meta["progress"]][0] == "ingestion"
    # a fresh store on the same directory (dashboard restart) still sees history and the report
    again = JobStore(tmp_path / "data")
    assert again.list_jobs()[0]["id"] == job_id
    assert again.result(job_id)["verdict"]["label"] == "high_risk"


def test_sandbox_scan_without_cluster_reports_gap_not_success(store):
    source = samples.resolve_source("benign-csv-stats")
    meta = finished(store, store.submit(source, "sandbox", sample_id="benign-csv-stats"))
    if meta["verdict"] != "inconclusive":  # only meaningful on machines without docker/kind/kubectl
        pytest.skip("this machine has a working sandbox")
    assert meta["status"] == "partial" and "No skill code was executed" in meta["error"]
    assert meta["outcome"] == "clean"  # benign expectation, but report says inconclusive


def test_running_jobs_are_marked_interrupted_after_restart(tmp_path):
    first = JobStore(tmp_path / "data")
    job_dir = first.jobs_dir / ("a" * 32)
    job_dir.mkdir(parents=True)
    (job_dir / "meta.json").write_text(json.dumps({"id": "a" * 32, "status": "running", "created_at": "x"}))
    second = JobStore(tmp_path / "data")
    assert second.get("a" * 32)["status"] == "interrupted"


def test_cancel_terminates_running_subprocess(tmp_path):
    stub = tmp_path / "stub.sh"
    stub.write_text("#!/bin/sh\nsleep 60\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    store = JobStore(tmp_path / "data", python=str(stub))
    job_id = store.submit("https://github.com/o/r", "quick")
    wait_for(lambda: store.get(job_id)["status"] == "running")
    started = time.time()
    store.cancel(job_id)
    meta = finished(store, job_id)
    assert meta["status"] == "cancelled" and time.time() - started < 15


def test_sandbox_jobs_run_one_at_a_time_and_queued_job_can_be_cancelled(tmp_path):
    stub = tmp_path / "stub.sh"
    stub.write_text("#!/bin/sh\nsleep 60\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    store = JobStore(tmp_path / "data", python=str(stub))
    first = store.submit("https://github.com/o/a", "sandbox")
    wait_for(lambda: store.get(first)["status"] == "running")
    second = store.submit("https://github.com/o/b", "sandbox")
    time.sleep(1)
    assert store.get(second)["status"] == "queued"
    store.cancel(second)
    assert finished(store, second)["status"] == "cancelled"
    store.cancel(first)
    finished(store, first)


def test_failed_scan_surfaces_the_error(store):
    meta = finished(store, store.submit("https://github.com/definitely-not-a-user-xyz/none-here-123", "quick"))
    assert meta["status"] == "failed" and meta["error"]


def test_batch_of_samples_reports_outcomes(store):
    batch_id = store.submit_batch(["sample:benign-csv-stats", "sample:runtime-env-dump", "sample:runtime-exfil-evasive"], "quick")
    batch = wait_for(lambda: (lambda b: b if b["status"] == "complete" else None)(store.get_batch(batch_id)), 90)
    by_label = {job["label"]: job for job in batch["jobs"]}
    assert by_label["benign-csv-stats"]["outcome"] == "clean"
    assert by_label["runtime-env-dump"]["outcome"] == "detected"
    assert by_label["runtime-exfil-evasive"]["outcome"] == "missed"  # needs a Sandbox Scan; honest in Quick mode
    assert batch["outcomes"] == {"clean": 1, "detected": 1, "missed": 1}


def test_batch_rejects_unknown_samples_and_bad_urls(store):
    with pytest.raises(ValueError):
        store.submit_batch(["sample:nope"], "quick")
    with pytest.raises(ValueError):
        store.submit_batch(["file:///etc"], "quick")
    with pytest.raises(ValueError):
        store.submit_batch(["  ", "# comment"], "quick")


def test_outcome_logic():
    assert outcome_for("malicious", "high_risk") == "detected"
    assert outcome_for("malicious", "inconclusive") == "missed"
    assert outcome_for("benign", "low_risk") == "clean"
    assert outcome_for("benign", "suspicious") == "false_positive"
    assert outcome_for(None, "malicious") is None


def test_url_validation():
    assert validate_public_git_url(" https://github.com/o/r/tree/main/x\u200b ") == "https://github.com/o/r/tree/main/x"
    for bad in ("http://github.com/o/r", "https://evil.com/o/r", "https://user:pw@github.com/o/r",
                "https://github.com/o/r?token=1", "/etc/passwd"):
        with pytest.raises(ValueError):
            validate_public_git_url(bad)


# ---------------------------------------------------------------- HTTP API
@pytest.fixture()
def api(tmp_path):
    server = make_server("127.0.0.1", 0, JobStore(tmp_path / "data"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % server.server_address[1]

    def call(method, path, body=None, content_type="application/json"):
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        request = urllib.request.Request(base + path, data=data, method=method, headers={"Content-Type": content_type})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.headers

    yield call
    server.shutdown()


def test_pages_render(api):
    for path in ("/", "/batch", "/history"):
        status, body, _ = api("GET", path)
        assert status == 200 and b"AgentGuard" in body
    status, body, _ = api("GET", "/")
    assert b'value="quick" checked' in body  # quick is the default mode


def test_api_rejects_form_posts_local_paths_and_bad_ids(api):
    assert api("POST", "/api/jobs", b"source=x", "application/x-www-form-urlencoded")[0] == 400
    assert api("POST", "/api/jobs", {"source": "/etc", "scan_mode": "quick"})[0] == 400
    assert api("POST", "/api/jobs", {"source": "sample:runtime-exfil-sink", "scan_mode": "bogus"})[0] == 400
    assert api("GET", "/api/jobs/not-an-id")[0] == 404
    assert api("GET", "/report/..%2f..%2fetc%2fpasswd")[0] == 404
    assert api("GET", "/nope")[0] == 404


def test_end_to_end_scan_report_and_downloads(api):
    status, body, _ = api("POST", "/api/jobs", {"source": "sample:runtime-env-dump", "scan_mode": "quick"})
    assert status == 202
    job_id = json.loads(body)["job_id"]
    meta = wait_for(lambda: (lambda m: m if m["status"] in {"complete", "partial", "failed"} else None)(json.loads(api("GET", "/api/jobs/" + job_id)[1])))
    assert meta["status"] == "complete" and meta["verdict"] == "high_risk"
    status, fragment, _ = api("GET", "/report/%s?fragment=1" % job_id)
    assert status == 200 and b"Static findings" in fragment and b"Remediation" in fragment
    status, document, headers = api("GET", "/report/%s/download.html" % job_id)
    assert status == 200 and b"<script" not in document and "attachment" in headers["Content-Disposition"]
    status, raw, _ = api("GET", "/report/%s/download.json" % job_id)
    assert json.loads(raw)["verdict"]["label"] == "high_risk"
    assert any(item["id"] == job_id for item in json.loads(api("GET", "/api/jobs")[1]))
    assert api("DELETE", "/api/jobs/" + job_id)[0] == 200
    assert api("GET", "/api/jobs/" + job_id)[0] == 404


def test_health_and_samples_endpoints(api):
    health = json.loads(api("GET", "/api/health")[1])
    assert {"tools", "cluster", "images", "sandbox_ready", "sandbox_problem"} <= set(health)
    listing = json.loads(api("GET", "/api/samples")[1])
    assert {item["expected"] for item in listing} == {"malicious", "benign"}
    assert all("path" not in item for item in listing)
