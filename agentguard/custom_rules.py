from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, Location

_CREDENTIAL = re.compile(
    r"(?:~[/\\]?\.ssh/id_(?:rsa|ed25519)|~[/\\]?\.aws[/\\]credentials|"
    r"~[/\\]?\.config[/\\]gcloud|os\.environ\s*\[[^]]*(?:AWS_|GCP_|AZURE_)|"
    r"\.netrc|\.pgpass|\.docker[/\\]config\.json)", re.I,
)
_NETWORK = re.compile(
    r"(?:requests\.(?:post|put)|urllib\.request\.urlopen|http\.client|"
    r"socket\.send|fetch\s*\(|axios\.post)", re.I,
)
_OBFUSCATION = re.compile(
    r"(?:base64\.b64encode|base64\.b64decode|codecs\.encode[^\n]{0,160}['\"]hex|"
    r"bytes\.fromhex|rot13|xor(?:-with-key|\s+with\s+key)?)", re.I,
)
_FRONTMATTER = re.compile(r"\A---\s*\r?\n")


def _finding(rule_id: str, category: str, severity: str, message: str, path: str, line: int,
             snippet: str, evidence: dict[str, object], remediation: str) -> Finding:
    return Finding(
        tool="agentguard", tool_version="0.1.0", finding_id=f"{rule_id}:{path}:{line}",
        rule_id=rule_id, category=category, severity=severity, message=message,
        description=f"AgentGuard native rule matched {path}.", remediation=remediation,
        location=Location(path=path, start_line=line, end_line=line, snippet=snippet),
        evidence=evidence,
    )


def _text_files(root: Path):
    for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts):
        try:
            yield path, path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue


def credential_chain(root: Path) -> list[Finding]:
    results = []
    for path, text in _text_files(root):
        source = _CREDENTIAL.search(text)
        sink = _NETWORK.search(text)
        if not source or not sink:
            continue
        line = text.count("\n", 0, sink.start()) + 1
        relative = path.relative_to(root).as_posix()
        results.append(_finding(
            "AG001", "credential_chain", "HIGH", "Credential source reaches a network sink",
            relative, line, text.splitlines()[line - 1].strip()[:500],
            {"credential": source.group(0), "network": sink.group(0)},
            "Remove the credential-to-network flow or document and constrain the intended destination.",
        ))
    return results


def obfuscation(root: Path) -> list[Finding]:
    results = []
    for path, text in _text_files(root):
        lines = text.splitlines()
        credential_lines = [i for i, line in enumerate(lines) if _CREDENTIAL.search(line)]
        network_lines = [i for i, line in enumerate(lines) if _NETWORK.search(line)]
        for match in _OBFUSCATION.finditer(text):
            line_index = text.count("\n", 0, match.start())
            if not any(abs(line_index - candidate) <= 20 for candidate in credential_lines + network_lines):
                continue
            relative = path.relative_to(root).as_posix()
            results.append(_finding(
                "AG002", "obfuscation", "HIGH",
                "Obfuscation is near a credential source or network sink", relative, line_index + 1,
                lines[line_index].strip()[:500], {"indicator": match.group(0)[:200]},
                "Decode and review the payload; remove unnecessary encoding or constrain its use.",
            ))
    return results


def malformed_frontmatter(root: Path) -> list[Finding]:
    path = root / "SKILL.md"
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    closing = next((i for i, line in enumerate(lines[1:], 1) if line.strip() == "---"), None)
    malformed = bool(_FRONTMATTER.match(text)) and closing is None
    if not malformed:
        try:
            import yaml
            if _FRONTMATTER.match(text) and closing is not None:
                yaml.safe_load("\n".join(lines[1:closing]))
        except (StopIteration, ValueError, TypeError):
            malformed = True
        except ModuleNotFoundError:
            # PyYAML is optional at runtime; retain a conservative structural
            # check so valid simple manifests are not rejected when absent.
            header = "\n".join(lines[1:closing])
            malformed = not all(re.search(rf"(?m)^\s*{field}\s*:", header) for field in ("name", "description"))
        except Exception:
            malformed = True
    if not malformed:
        return []
    return [_finding(
        "AG003", "malformed_frontmatter", "MEDIUM",
        "SKILL.md frontmatter is malformed or missing its closing delimiter", "SKILL.md", 1,
        lines[0].strip() if lines else "", {},
        "Add valid YAML frontmatter with a closing --- delimiter.",
    )]


def incomplete_scan(root: Path, *, nvidia_report: dict | None, cisco_report: dict | None) -> list[Finding]:
    nvidia_empty = isinstance(nvidia_report, dict) and not nvidia_report.get("components")
    cisco_empty = isinstance(cisco_report, dict) and not cisco_report.get("analyzers_used")
    if not (nvidia_empty and cisco_empty):
        return []
    return [
        _finding("AG004", "incomplete_scan", "LOW",
                 "NVIDIA reports no analyzed components", "NVIDIA", 1, "", {},
                 "Treat this result as incomplete and verify that the input was recognized."),
        _finding("AG004", "incomplete_scan", "LOW",
                 "Cisco reports no analyzers used", "Cisco", 1, "", {},
                 "Treat this result as incomplete and verify that the input was recognized."),
    ]


def scan_directory(root: Path, *, nvidia_report: dict | None = None,
                   cisco_report: dict | None = None) -> list[Finding]:
    return (credential_chain(root) + obfuscation(root) + malformed_frontmatter(root)
            + incomplete_scan(root, nvidia_report=nvidia_report, cisco_report=cisco_report))
