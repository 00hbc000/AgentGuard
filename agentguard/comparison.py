from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .normalize import SEVERITIES


def _max_severity(findings: list[dict[str, Any]]) -> str:
    rank = {value: index for index, value in enumerate(SEVERITIES)}
    return max((str(item.get("severity", "INFO")) for item in findings), key=lambda value: rank.get(value, 0), default="INFO")


def _record(fixture_id: str, tool: str, label: str, findings: list[dict[str, Any]], *,
            parse_ok: bool, exit_code: int | None, notes: str = "") -> dict[str, Any]:
    return {
        "fixture_id": fixture_id, "tool": tool, "label": label,
        "expected_signals": [], "observed_findings": len(findings),
        "observed_categories": sorted({str(item.get("category", "unknown")) for item in findings}),
        "max_severity": _max_severity(findings), "parse_ok": parse_ok,
        "exit_code": exit_code, "notes": notes,
    }


def build_comparison(input_dir: Path, output_path: Path) -> Path:
    records = []
    for report_path in sorted(input_dir.glob("*.json")):
        if report_path.name.endswith(".meta.json"):
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        fixture_id = str(report.get("fixture_id") or report_path.stem)
        label = str(report.get("label", "unknown"))
        expected_signals: list[str] = []
        fixture_path = report.get("fixture_path")
        manifest_path = Path(fixture_path) / "manifest.json" if fixture_path else None
        if manifest_path and manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                label = str(manifest.get("label", label))
                expected_signals = [str(item) for item in manifest.get("expected_categories", [])]
            except (OSError, json.JSONDecodeError):
                pass
        records.append(_record(fixture_id, "agentguard", label, report.get("findings", []),
                               parse_ok=True, exit_code=0, notes=report.get("scan_status", "")))
        records[-1]["expected_signals"] = expected_signals
        for run in report.get("tool_runs", []):
            raw = run.get("raw_report") or {}
            findings = raw.get("findings", []) if run.get("tool") == "cisco" else raw.get("issues", [])
            records.append(_record(fixture_id, run.get("tool", "unknown"), label, findings,
                                   parse_ok=bool(run.get("raw_report")), exit_code=run.get("exit_code"),
                                   notes=run.get("error") or run.get("status", "")))
            records[-1]["expected_signals"] = expected_signals
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    return output_path
