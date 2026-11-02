"""Durable scan jobs for the dashboard.

Every scan runs as a separate ``python -m agentguard.cli scan`` subprocess, so it can be cancelled
(SIGTERM makes the CLI delete its sandbox pod), survives dashboard bugs, and never shares memory
with the web server. Job state lives on disk under ``<data_dir>/jobs/<id>/`` so history and reports
survive restarts; jobs that were running when the server stopped are marked ``interrupted``.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import samples as sample_library
from .ingest import IngestionError, list_skills

MODES = ("quick", "sandbox", "deep")
TERMINAL = {"complete", "partial", "failed", "cancelled", "interrupted"}
ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
MAX_BATCH_SKILLS = 50
REPO_ROOT = Path(__file__).resolve().parents[1]
_DETECTED_LABELS = {"malicious", "high_risk", "suspicious"}


def clean_source(source: str) -> str:
    return source.strip().replace("\u200b", "").replace("\ufeff", "")


def validate_public_git_url(source: str) -> str:
    cleaned = clean_source(source)
    parsed = urlparse(cleaned)
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "gitlab.com", "bitbucket.org"}:
        raise ValueError("Only public HTTPS GitHub, GitLab, and Bitbucket URLs (or a sample from the library) are accepted.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Repository URLs must not contain credentials, query strings, or fragments.")
    return cleaned


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def outcome_for(expected: str | None, verdict: str | None) -> str | None:
    """Compare a verdict with a sample's known label so batches show detected / missed / false positive."""
    if not expected or not verdict:
        return None
    if expected == "malicious":
        return "detected" if verdict in _DETECTED_LABELS else "missed"
    if expected == "benign":
        return "false_positive" if verdict in _DETECTED_LABELS else "clean"
    return None


class JobStore:
    def __init__(self, data_dir: Path, *, python: str | None = None, max_parallel_static: int = 3) -> None:
        self.data_dir = Path(data_dir)
        self.jobs_dir = self.data_dir / "jobs"
        self.batches_dir = self.data_dir / "batches"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.batches_dir.mkdir(parents=True, exist_ok=True)
        self.python = python or sys.executable
        self._lock = threading.RLock()
        self._static_slots = threading.Semaphore(max_parallel_static)
        self._sandbox_lock = threading.Lock()  # one pod at a time: the sink and policies are shared
        self._processes: dict[str, subprocess.Popen[bytes]] = {}
        self._cancelled: set[str] = set()
        self.recover()

    # ------------------------------------------------------------------ persistence
    def _job_dir(self, job_id: str) -> Path:
        if not ID_PATTERN.match(job_id):
            raise KeyError(job_id)
        return self.jobs_dir / job_id

    def _meta(self, job_id: str) -> dict[str, Any]:
        meta = _read_json(self._job_dir(job_id) / "meta.json")
        if meta is None:
            raise KeyError(job_id)
        return meta

    def _update(self, job_id: str, **changes: Any) -> dict[str, Any]:
        with self._lock:
            meta = self._meta(job_id)
            meta.update(changes)
            _write_json(self._job_dir(job_id) / "meta.json", meta)
            return meta

    def recover(self) -> None:
        """Mark jobs and batches that were in flight when the server stopped."""
        for path in self.jobs_dir.glob("*/meta.json"):
            meta = _read_json(path)
            if meta and meta.get("status") in {"queued", "running"}:
                meta.update(status="interrupted", finished_at=_now(),
                            error="The dashboard restarted while this scan was in progress. "
                                  "Re-run it; a leftover sandbox pod (if any) is removed on the next sandbox scan.")
                _write_json(path, meta)
        for path in self.batches_dir.glob("*.json"):
            batch = _read_json(path)
            if batch and batch.get("status") == "expanding":
                batch.update(status="interrupted", error="The dashboard restarted while expanding this batch.")
                _write_json(path, batch)

    # ------------------------------------------------------------------ jobs
    def submit(self, source: str, scan_mode: str, *, sample_id: str | None = None,
               label: str | None = None, batch_id: str | None = None) -> str:
        """Queue a scan. ``source`` must already be validated (public URL or a library sample path)."""
        if scan_mode not in MODES:
            raise ValueError("scan_mode must be quick, sandbox, or deep")
        job_id = uuid.uuid4().hex
        directory = self._job_dir(job_id)
        (directory / "out").mkdir(parents=True)
        sample = sample_library.get(sample_id) if sample_id else None
        meta = {
            "id": job_id,
            "source": (sample or {}).get("url") or (sample or {}).get("path") or source,
            "label": label or (sample or {}).get("label") or source.rstrip("/").rsplit("/", 1)[-1],
            "sample_id": sample_id, "expected": (sample or {}).get("expected"),
            "scan_mode": scan_mode, "batch_id": batch_id,
            "status": "queued", "created_at": _now(), "started_at": None, "finished_at": None,
            "error": None, "exit_code": None, "report": None,
            "verdict": None, "severity": None, "finding_count": None, "scan_status": None, "outcome": None,
        }
        _write_json(directory / "meta.json", meta)
        threading.Thread(target=self._run, args=(job_id, source, scan_mode), daemon=True,
                         name="scan-" + job_id[:8]).start()
        return job_id

    def _acquire(self, job_id: str, lock: Any) -> bool:
        while not lock.acquire(timeout=0.5):
            if job_id in self._cancelled:
                return False
        return True

    def _run(self, job_id: str, source: str, scan_mode: str) -> None:
        directory = self._job_dir(job_id)
        held: list[Any] = []
        try:
            lock = self._static_slots if scan_mode == "quick" else self._sandbox_lock
            if not self._acquire(job_id, lock):
                self._update(job_id, status="cancelled", finished_at=_now(), error="Cancelled while queued")
                return
            held.append(lock)
            if job_id in self._cancelled:
                self._update(job_id, status="cancelled", finished_at=_now(), error="Cancelled while queued")
                return
            self._update(job_id, status="running", started_at=_now())
            command = [self.python, "-m", "agentguard.cli", "scan", source, "--output", str(directory / "out"),
                       "--mode", scan_mode, "--progress-file", str(directory / "progress.jsonl"),
                       "--fail-on-severity", "CRITICAL"]
            env = {**os.environ, "PYTHONPATH": str(REPO_ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""),
                   "PYTHONUNBUFFERED": "1"}
            with (directory / "stdout.log").open("wb") as out, (directory / "stderr.log").open("wb") as err:
                process = subprocess.Popen(command, cwd=str(REPO_ROOT), stdout=out, stderr=err, env=env)
                with self._lock:
                    self._processes[job_id] = process
                    cancelled_early = job_id in self._cancelled
                if cancelled_early:
                    process.terminate()
                code = process.wait()
            self._finish(job_id, code)
        except Exception as exc:  # never leave a job stuck in "running"
            self._update(job_id, status="failed", finished_at=_now(), error="Dashboard error: %s" % exc)
        finally:
            with self._lock:
                self._processes.pop(job_id, None)
            for held_lock in held:
                held_lock.release()

    def _finish(self, job_id: str, code: int) -> None:
        directory = self._job_dir(job_id)
        meta = self._meta(job_id)
        if job_id in self._cancelled:
            self._update(job_id, status="cancelled", finished_at=_now(), exit_code=code, error="Cancelled by user")
            return
        report = None
        stdout_path = directory / "stdout.log"
        stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
        match = re.search(r'"report":\s*"([^"]+)"', stdout)
        if match and Path(match.group(1)).is_file():
            report = Path(match.group(1))
        if report is None:
            candidates = sorted((directory / "out").glob("*.json"))
            report = candidates[0] if candidates else None
        if report is None:
            stderr = (directory / "stderr.log").read_text(encoding="utf-8", errors="replace")
            self._update(job_id, status="failed", finished_at=_now(), exit_code=code,
                         error=(stderr.strip().splitlines() or ["Scan produced no report"])[-1][:500])
            return
        result = _read_json(report) or {}
        verdict = (result.get("verdict") or {}).get("label")
        scan_status = result.get("scan_status")
        dynamic_stage = (result.get("stages", {}) or {}).get("dynamic", {}) or {}
        self._update(
            job_id, status="complete" if scan_status == "complete" else "partial", finished_at=_now(),
            exit_code=code, report=str(report.relative_to(self.data_dir)), verdict=verdict,
            severity=result.get("aggregate_severity"), finding_count=result.get("finding_count"),
            scan_status=scan_status, outcome=outcome_for(meta.get("expected"), verdict),
            error=dynamic_stage.get("reason") if scan_status == "error" else None,
        )

    def progress(self, job_id: str) -> list[dict[str, Any]]:
        path = self._job_dir(job_id) / "progress.jsonl"
        events = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass
        return events

    def get(self, job_id: str) -> dict[str, Any]:
        meta = self._meta(job_id)
        meta["progress"] = self.progress(job_id)
        return meta

    def result(self, job_id: str) -> dict[str, Any] | None:
        meta = self._meta(job_id)
        if not meta.get("report"):
            return None
        return _read_json(self.data_dir / meta["report"])

    def report_file(self, job_id: str) -> Path | None:
        meta = self._meta(job_id)
        path = self.data_dir / meta["report"] if meta.get("report") else None
        return path if path and path.is_file() else None

    def list_jobs(self, limit: int = 500) -> list[dict[str, Any]]:
        jobs = []
        for path in self.jobs_dir.glob("*/meta.json"):
            meta = _read_json(path)
            if meta:
                jobs.append(meta)
        jobs.sort(key=lambda item: item.get("created_at", ""), reverse=True)
        return jobs[:limit]

    def cancel(self, job_id: str) -> dict[str, Any]:
        meta = self._meta(job_id)
        if meta["status"] in TERMINAL:
            return meta
        with self._lock:
            self._cancelled.add(job_id)
            process = self._processes.get(job_id)
        if process is not None and process.poll() is None:
            process.terminate()  # SIGTERM: the CLI deletes the sandbox pod before exiting

            def _kill_later() -> None:
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()

            threading.Thread(target=_kill_later, daemon=True).start()
        return self._meta(job_id)

    def delete(self, job_id: str) -> None:
        meta = self._meta(job_id)
        if meta["status"] not in TERMINAL:
            raise ValueError("Cancel the job before deleting it")
        shutil.rmtree(self._job_dir(job_id), ignore_errors=True)

    # ------------------------------------------------------------------ batches
    def submit_batch(self, inputs: list[str], scan_mode: str, *, expand: bool = True) -> str:
        if scan_mode not in MODES:
            raise ValueError("scan_mode must be quick, sandbox, or deep")
        entries = []
        for raw in inputs:
            value = clean_source(raw)
            if not value or value.startswith("#"):
                continue
            if value.startswith("sample:"):
                sample_id = value.split(":", 1)[1].strip()
                if sample_library.get(sample_id) is None:
                    raise ValueError("Unknown sample: %s" % sample_id)
                entries.append("sample:" + sample_id)
            else:
                entries.append(validate_public_git_url(value))
        if not entries:
            raise ValueError("Provide at least one URL or sample")
        batch_id = uuid.uuid4().hex
        batch = {"id": batch_id, "created_at": _now(), "scan_mode": scan_mode, "inputs": entries,
                 "expand": expand, "status": "expanding", "job_ids": [], "errors": [], "error": None}
        _write_json(self.batches_dir / (batch_id + ".json"), batch)
        threading.Thread(target=self._run_batch, args=(batch_id,), daemon=True, name="batch-" + batch_id[:8]).start()
        return batch_id

    def _save_batch(self, batch: dict[str, Any]) -> None:
        with self._lock:
            _write_json(self.batches_dir / (batch["id"] + ".json"), batch)

    def _run_batch(self, batch_id: str) -> None:
        batch = _read_json(self.batches_dir / (batch_id + ".json")) or {}
        targets: list[tuple[str, str | None, str | None]] = []  # (source, sample_id, label)
        for entry in batch.get("inputs", []):
            if entry.startswith("sample:"):
                sample_id = entry.split(":", 1)[1]
                targets.append((sample_library.resolve_source(sample_id), sample_id, None))
                continue
            path = urlparse(entry).path
            if not batch.get("expand") or "/tree/" in path or "/blob/" in path or "/-/" in path:
                targets.append((entry, None, None))
                continue
            try:
                with tempfile.TemporaryDirectory(prefix="agentguard-batch-") as workspace:
                    skills = list_skills(entry, Path(workspace))
            except (IngestionError, OSError, subprocess.SubprocessError) as exc:
                batch["errors"].append("Could not list skills in %s: %s" % (entry, exc))
                targets.append((entry, None, None))
                continue
            if not skills:
                batch["errors"].append("No SKILL.md found in %s; scanning it as a single skill." % entry)
                targets.append((entry, None, None))
            targets.extend((item["url"], None, item["name"]) for item in skills)
        if len(targets) > MAX_BATCH_SKILLS:
            batch["errors"].append("Batch limited to %d skills; %d were not queued."
                                   % (MAX_BATCH_SKILLS, len(targets) - MAX_BATCH_SKILLS))
            targets = targets[:MAX_BATCH_SKILLS]
        for source, sample_id, label in targets:
            try:
                batch["job_ids"].append(self.submit(source, batch["scan_mode"], sample_id=sample_id,
                                                    label=label, batch_id=batch_id))
            except ValueError as exc:
                batch["errors"].append(str(exc))
        batch["status"] = "running"
        self._save_batch(batch)

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        if not ID_PATTERN.match(batch_id):
            raise KeyError(batch_id)
        batch = _read_json(self.batches_dir / (batch_id + ".json"))
        if batch is None:
            raise KeyError(batch_id)
        jobs = []
        for job_id in batch.get("job_ids", []):
            try:
                jobs.append(self._meta(job_id))
            except KeyError:
                continue
        counts: dict[str, int] = {}
        outcomes: dict[str, int] = {}
        for job in jobs:
            counts[job["status"]] = counts.get(job["status"], 0) + 1
            if job.get("outcome"):
                outcomes[job["outcome"]] = outcomes.get(job["outcome"], 0) + 1
        if batch["status"] == "running" and jobs and all(job["status"] in TERMINAL for job in jobs):
            batch["status"] = "complete"
        batch.update(jobs=jobs, counts=counts, outcomes=outcomes, total=len(jobs))
        return batch

    def list_batches(self) -> list[dict[str, Any]]:
        batches = []
        for path in self.batches_dir.glob("*.json"):
            batch = _read_json(path)
            if batch:
                try:
                    batches.append(self.get_batch(batch["id"]))
                except KeyError:
                    continue
        for batch in batches:
            batch.pop("jobs", None)
        batches.sort(key=lambda item: item.get("created_at", ""), reverse=True)
        return batches

    def cancel_batch(self, batch_id: str) -> dict[str, Any]:
        batch = self.get_batch(batch_id)
        for job_id in batch["job_ids"]:
            self.cancel(job_id)
        return self.get_batch(batch_id)

    def stop_all(self) -> None:
        """Terminate running scans (used on dashboard shutdown) so no sandbox pod is left behind."""
        with self._lock:
            processes = list(self._processes.values())
            self._cancelled.update(self._processes)
        for process in processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
        deadline = time.time() + 20
        for process in processes:
            try:
                process.wait(timeout=max(0.1, deadline - time.time()))
            except subprocess.TimeoutExpired:
                process.kill()
