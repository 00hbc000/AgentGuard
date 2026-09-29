from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .custom_rules import scan_directory
from .ingest import IngestionError, materialize
from .models import Finding, ScanResult, ToolRun
from .normalize import aggregate_severity, normalize_cisco, normalize_nvidia

TOOL_VERSIONS = {"cisco": "2.1.0", "nvidia": "2.12.0", "agentguard": "0.1.0"}
TIMEOUTS = {"cisco": 300, "nvidia": 180}


def _command_from_env(name: str) -> list[str] | None:
    value = os.environ.get(name, "").strip()
    return shlex.split(value) if value else None


def _parse_json(stdout: str) -> dict[str, Any] | None:
    candidates = [stdout.strip()]
    candidates.extend(line.strip() for line in stdout.splitlines() if line.strip().startswith("{"))
    for candidate in reversed(candidates):
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _run_external(tool: str, command: list[str], root: Path, output_dir: Path) -> tuple[ToolRun, dict[str, Any] | None, list[Finding]]:
    started_at = datetime.now(timezone.utc)
    started = time.perf_counter()
    args = [*command, str(root), "--format", "json"]
    if tool == "cisco":
        args.append("--use-behavioral")
    else:
        args.append("--no-llm")
    try:
        completed = subprocess.run(args, capture_output=True, text=True,
                                   timeout=TIMEOUTS[tool], check=False)
        raw_report = _parse_json(completed.stdout)
        duration_ms = round((time.perf_counter() - started) * 1000)
        status = "completed" if raw_report is not None else "failed"
        run = ToolRun(
            tool=tool, tool_version=TOOL_VERSIONS[tool], status=status, command=args,
            exit_code=completed.returncode, duration_ms=duration_ms,
            stdout=completed.stdout, stderr=completed.stderr, raw_report=raw_report,
            error=None if raw_report is not None else "Scanner did not emit a JSON object",
        )
        normalized = normalize_cisco(raw_report, TOOL_VERSIONS[tool]) if tool == "cisco" and raw_report else normalize_nvidia(raw_report or {}, TOOL_VERSIONS[tool]) if tool == "nvidia" and raw_report else []
        return run, raw_report, normalized
    except subprocess.TimeoutExpired as exc:
        duration_ms = round((time.perf_counter() - started) * 1000)
        return ToolRun(
            tool=tool, tool_version=TOOL_VERSIONS[tool], status="failed", command=args,
            exit_code=None, duration_ms=duration_ms,
            stdout=exc.stdout or "", stderr=exc.stderr or "", error="timeout",
        ), None, []
    except OSError as exc:
        duration_ms = round((time.perf_counter() - started) * 1000)
        return ToolRun(
            tool=tool, tool_version=TOOL_VERSIONS[tool], status="failed", command=args,
            exit_code=None, duration_ms=duration_ms, stdout="", stderr="", error=str(exc),
        ), None, []


def _status(findings: list[Finding], tool_runs: list[ToolRun], root: Path) -> str:
    if not tool_runs:
        return "complete" if (root / "SKILL.md").is_file() else "incomplete"
    if all(run.status == "failed" for run in tool_runs):
        return "error"
    return "complete" if any(run.status == "completed" for run in tool_runs) else "incomplete"


def scan(source: str, *, workspace_base: Path | None = None, include_external: bool = True,
         output_dir: Path | None = None) -> ScanResult:
    scan_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    base = workspace_base or Path(tempfile.mkdtemp(prefix="agentguard-run-"))
    base.mkdir(parents=True, exist_ok=True)
    root, ingestion = materialize(source, base)
    tool_runs: list[ToolRun] = []
    findings: list[Finding] = []
    reports: dict[str, dict[str, Any] | None] = {"cisco": None, "nvidia": None}
    configured = (("cisco", _command_from_env("AGENTGUARD_CISCO_COMMAND")),
                 ("nvidia", _command_from_env("AGENTGUARD_NVIDIA_COMMAND")))
    if include_external:
        for tool, command in configured:
            if command is None:
                tool_runs.append(ToolRun(tool=tool, tool_version=TOOL_VERSIONS[tool], status="skipped",
                                         command=[], exit_code=None, duration_ms=0, stdout="", stderr="",
                                         error="Not configured"))
                continue
            run, report, normalized = _run_external(tool, command, root, output_dir or base)
            tool_runs.append(run)
            reports[tool] = report
            findings.extend(normalized)
    native = scan_directory(root, nvidia_report=reports["nvidia"], cisco_report=reports["cisco"])
    findings.extend(native)
    status = _status(findings, tool_runs if include_external else [], root)
    return ScanResult(scan_id=scan_id, source=source, materialized_path=str(root),
                      created_at=created_at, findings=findings, tool_runs=tool_runs,
                      ingestion=ingestion, scan_status=status,
                      aggregate_severity=aggregate_severity(findings))


def write_result(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{Path(result.source).stem or result.scan_id}.json"
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    for run in result.tool_runs:
        if run.status == "skipped":
            continue
        (output_dir / f"{path.stem}.{run.tool}.stdout").write_text(run.stdout, encoding="utf-8")
        (output_dir / f"{path.stem}.{run.tool}.stderr").write_text(run.stderr, encoding="utf-8")
    (output_dir / f"{path.stem}.meta.json").write_text(json.dumps({
        "scan_id": result.scan_id, "source": result.source, "created_at": result.created_at,
        "scan_status": result.scan_status, "aggregate_severity": result.aggregate_severity,
        "tool_runs": [run.to_dict() for run in result.tool_runs],
    }, indent=2), encoding="utf-8")
    return path


def scan_all(source_dir: str, output_dir: Path, *, include_external: bool = True) -> list[Path]:
    root = Path(source_dir)
    if not root.is_dir():
        raise IngestionError(f"Input directory does not exist: {source_dir}")
    paths = sorted(path for path in root.iterdir() if path.is_dir() or path.suffix.lower() in {".zip", ".tar", ".gz"})
    results = []
    for path in paths:
        try:
            result = scan(str(path), include_external=include_external, output_dir=output_dir)
            results.append(write_result(result, output_dir))
        except IngestionError:
            raise
    return results
