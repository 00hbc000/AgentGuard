from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import re
from pathlib import Path
from typing import Any


@dataclass
class Location:
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    snippet: str | None = None


@dataclass
class Finding:
    tool: str
    finding_id: str
    rule_id: str
    category: str
    severity: str
    message: str
    description: str | None = None
    confidence: float | None = None
    remediation: str | None = None
    location: Location = field(default_factory=Location)
    evidence: dict[str, Any] = field(default_factory=dict)
    raw_finding: dict[str, Any] = field(default_factory=dict)
    tool_version: str = "unknown"

    @property
    def fingerprint(self) -> str:
        message = re.sub(r"\s+", " ", self.message).strip()
        value = "|".join((self.rule_id, self.location.path or "", str(self.location.start_line), message))
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "tool_version": self.tool_version,
            "analyzer": self.raw_finding.get("analyzer", self.tool),
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "file_path": self.location.path or "",
            "line_number": self.location.start_line,
            "message": self.message,
            "evidence": (self.evidence.get("text") if set(self.evidence) == {"text"}
                         else json.dumps(self.evidence, sort_keys=True) if self.evidence else None),
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
            "raw": self.raw_finding,
        }


@dataclass
class ToolRun:
    tool: str
    status: str
    command: list[str]
    exit_code: int | None
    duration_ms: int
    stdout: str
    stderr: str
    raw_report: dict[str, Any] | None = None
    error: str | None = None
    tool_version: str = "unknown"
    report_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    scan_id: str
    source: str
    materialized_path: str
    created_at: str
    findings: list[Finding]
    tool_runs: list[ToolRun]
    ingestion: dict[str, Any]
    scan_status: str = "complete"
    aggregate_severity: str = "INFO"

    def to_dict(self) -> dict[str, Any]:
        tools_used = [run.tool for run in self.tool_runs if run.status == "completed"]
        if "agentguard" not in tools_used:
            tools_used.append("agentguard")
        return {
            "fixture_id": Path(self.source).stem or self.scan_id,
            "fixture_path": self.materialized_path,
            "scanned_at_utc": self.created_at,
            "tools_used": tools_used,
            "tool_versions": {**{run.tool: run.tool_version for run in self.tool_runs}, "agentguard": "0.1.0"},
            "scan_status": self.scan_status,
            "aggregate_severity": self.aggregate_severity,
            "finding_count": len(self.findings),
            "findings": [finding.to_dict() for finding in self.findings],
            "scan_id": self.scan_id,
            "source": self.source,
            "materialized_path": self.materialized_path,
            "created_at": self.created_at,
            "tool_runs": [run.to_dict() for run in self.tool_runs],
            "ingestion": self.ingestion,
        }
