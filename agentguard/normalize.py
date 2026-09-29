from __future__ import annotations

from typing import Any

from .models import Finding, Location

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_RANK = {value: index for index, value in enumerate(SEVERITIES)}


def normalize_severity(value: Any) -> str:
    value = str(value or "INFO").strip().upper()
    if value in {"NONE", "SAFE"}:
        return "INFO"
    if value == "WARNING":
        return "MEDIUM"
    return value if value in _RANK else "INFO"


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _location(item: dict[str, Any]) -> Location:
    location = item.get("location") or {}
    if isinstance(location, list):
        location = location[0] if location else {}
    if not isinstance(location, dict):
        location = {}
    return Location(
        path=item.get("file_path") or item.get("file") or location.get("file") or location.get("path"),
        start_line=_integer(item.get("line_number") or item.get("start_line") or location.get("start_line")),
        end_line=_integer(item.get("end_line") or location.get("end_line")),
        snippet=item.get("snippet") or item.get("matched_text") or location.get("snippet"),
    )


def normalize_cisco(report: dict[str, Any], tool_version: str = "2.1.0") -> list[Finding]:
    result: list[Finding] = []
    for item in report.get("findings", []) if isinstance(report, dict) else []:
        if not isinstance(item, dict):
            continue
        result.append(Finding(
            tool="cisco", tool_version=tool_version,
            finding_id=str(item.get("id") or item.get("finding_id") or item.get("rule_id") or "unknown"),
            rule_id=str(item.get("rule_id") or item.get("id") or "UNKNOWN"),
            category=str(item.get("category") or "unknown"),
            severity=normalize_severity(item.get("severity")),
            message=str(item.get("title") or item.get("message") or "Cisco finding"),
            description=item.get("description"), confidence=item.get("confidence"),
            remediation=item.get("remediation"), location=_location(item),
            evidence=item.get("metadata") if isinstance(item.get("metadata"), dict) else {},
            raw_finding=item,
        ))
    return result


def normalize_nvidia(report: dict[str, Any], tool_version: str = "2.12.0") -> list[Finding]:
    result: list[Finding] = []
    for item in report.get("issues", []) if isinstance(report, dict) else []:
        if not isinstance(item, dict):
            continue
        location = item.get("location") if isinstance(item.get("location"), dict) else {}
        normalized = dict(item)
        normalized["file_path"] = location.get("file") or item.get("file")
        normalized["line_number"] = location.get("start_line") or item.get("start_line")
        normalized["snippet"] = item.get("code_snippet") or item.get("snippet") or item.get("evidence")
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        for key in ("finding", "explanation", "code_snippet"):
            if item.get(key) is not None:
                evidence[key] = item[key]
        message = item.get("message") or item.get("title") or item.get("pattern") or item.get("finding") or item.get("explanation") or "SkillSpector finding"
        result.append(Finding(
            tool="nvidia", tool_version=tool_version,
            # NVIDIA finding_id is intentionally retained only in raw_finding.
            finding_id="", rule_id=str(item.get("rule_id") or item.get("id") or "UNKNOWN"),
            category=str(item.get("category") or "unknown"),
            severity=normalize_severity(item.get("severity")),
            message=str(message),
            description=item.get("description") or item.get("explanation") or item.get("message"),
            confidence=item.get("confidence"), remediation=item.get("remediation"),
            location=_location(normalized),
            evidence=evidence,
            raw_finding=item,
        ))
    return result


def normalize_agentguard(items: list[Finding]) -> list[Finding]:
    return items


def aggregate_severity(findings: list[Finding]) -> str:
    return max((finding.severity for finding in findings), key=lambda value: _RANK[value], default="INFO")
