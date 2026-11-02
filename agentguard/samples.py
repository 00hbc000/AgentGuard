"""Sample library for the dashboard: known-malicious and known-benign skills to test with.

Local samples live in ``samples/`` and are synthetic. Remote entries are public repositories that
publish deliberately malicious skills for scanner testing (Trail of Bits, a community corpus, and
Cisco's evaluation set) plus benign controls. Remote skills are only ever *downloaded*; their code
runs only inside the Kubernetes sandbox.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"

_TOB = "https://github.com/trailofbits/overtly-malicious-skills/tree/main/skills/"
_CORPUS = "https://github.com/elliottwaves-20/agent-guard-corpus/tree/main/malicious/"
_CISCO = "https://github.com/cisco-ai-defense/skill-scanner/tree/main/evals/skills/"
_ANTHROPIC = "https://github.com/anthropics/skills/tree/main/skills/"


def _local(sample_id: str, label: str, expected: str, shows: str) -> dict[str, Any]:
    return {"id": sample_id, "label": label, "group": "Local fixtures (synthetic)", "kind": "local",
            "path": f"samples/{sample_id}", "expected": expected, "shows": shows}


def _remote(sample_id: str, label: str, group: str, url: str, expected: str, shows: str) -> dict[str, Any]:
    return {"id": sample_id, "label": label, "group": group, "kind": "remote", "url": url,
            "expected": expected, "shows": shows}


SAMPLES: list[dict[str, Any]] = [
    _local("benign-csv-stats", "benign-csv-stats", "benign",
           "Control: sandbox runs its command, nothing is flagged."),
    _local("runtime-exfil-evasive", "runtime-exfil-evasive", "malicious",
           "Static rules see nothing; Sandbox Scan proves exfiltration (CRITICAL)."),
    _local("runtime-exfil-sink", "runtime-exfil-sink", "malicious",
           "Honeypot credentials reach the sink: CRITICAL DYN_HONEYPOT_EXFIL."),
    _local("runtime-exfil-external", "runtime-exfil-external", "malicious",
           "Exfiltration to a blocked external host: HIGH attempt, not proof."),
    _local("runtime-env-dump", "runtime-env-dump", "malicious",
           "Prints canary environment variables: HIGH DYN_ENV_EXPOSED."),
    _remote("tob-csv-summarizer", "csv-summarizer", "Trail of Bits - overtly malicious skills", _TOB + "csv-summarizer",
            "malicious", "Environment dump hidden below ~100,000 blank lines (AG005 + AG006)."),
    _remote("tob-context-loader", "context-loader", "Trail of Bits - overtly malicious skills", _TOB + "context-loader",
            "malicious", "Malicious script inside a hidden .docx archive (AG007)."),
    _remote("tob-simple-formatter", "simple-formatter", "Trail of Bits - overtly malicious skills", _TOB + "simple-formatter",
            "malicious", "Python bytecode that does not match its source (AG007)."),
    _remote("tob-dev-env-setup", "dev-env-setup", "Trail of Bits - overtly malicious skills", _TOB + "dev-env-setup",
            "malicious", "Registry redirected to an attacker-controlled host (AG008)."),
    _remote("corpus-m1-exfil", "m1-exfil", "agent-guard-corpus", _CORPUS + "m1-exfil", "malicious",
            "Reads ~/.aws and ~/.ssh and POSTs them out (AG001 + AG005)."),
    _remote("corpus-m2-injection", "m2-injection", "agent-guard-corpus", _CORPUS + "m2-injection", "malicious",
            "Hidden HTML-comment instruction to cat SSH keys (AG009)."),
    _remote("corpus-m3-curlsh", "m3-curlsh", "agent-guard-corpus", _CORPUS + "m3-curlsh", "malicious",
            "curl | sudo bash installer (AG008)."),
    _remote("corpus-m4-obfuscated", "m4-obfuscated", "agent-guard-corpus", _CORPUS + "m4-obfuscated", "malicious",
            "Aliased base64 decode feeding exec (AG010)."),
    _remote("corpus-m5-subtle", "m5-subtle", "agent-guard-corpus", _CORPUS + "m5-subtle", "malicious",
            "Direct-URL npm install and env piped to base64 in a reference doc (AG005 + AG008)."),
    _remote("cisco-environment-dump", "environment-dump", "Cisco skill-scanner evals",
            _CISCO + "data-exfiltration/environment-dump", "malicious", "Bulk environment dump (AG005)."),
    _remote("cisco-environment-secrets", "environment-secrets", "Cisco skill-scanner evals",
            _CISCO + "data-exfiltration/environment-secrets", "malicious", "Reads /etc/shadow (AG011)."),
    _remote("cisco-base64-payload", "base64-payload", "Cisco skill-scanner evals",
            _CISCO + "obfuscation/base64-payload", "malicious", "XOR + dynamic compile of caller source (AG010)."),
    _remote("cisco-eval-execution", "eval-execution", "Cisco skill-scanner evals",
            _CISCO + "command-injection/eval-execution", "malicious", "Compiles caller-supplied expression (AG010)."),
    _remote("cisco-registry-redirect", "registry-redirect", "Cisco skill-scanner evals",
            _CISCO + "supply-chain-attack/registry-redirect", "malicious", "Package registry override (AG008)."),
    _remote("cisco-jailbreak-override", "jailbreak-override", "Cisco skill-scanner evals",
            _CISCO + "prompt-injection/jailbreak-override", "malicious", "Instruction to conceal an action from the user (AG009)."),
    _remote("cisco-encoded-tag", "encoded-tag", "Cisco skill-scanner evals",
            _CISCO + "unicode-steganography/encoded-tag", "malicious", "Escaped Unicode Tag-block character (AG006)."),
    _remote("cisco-simple-math", "simple-math", "Benign public controls", _CISCO + "safe-skills/simple-math",
            "benign", "Control from Cisco's eval set: no findings."),
    _remote("anthropic-skill-creator", "anthropics/skills - skill-creator", "Benign public controls",
            _ANTHROPIC + "skill-creator", "benign", "Official skill with 10 scripts: should produce no findings."),
    _remote("anthropic-brand-guidelines", "anthropics/skills - brand-guidelines", "Benign public controls",
            _ANTHROPIC + "brand-guidelines", "benign",
            "Prompt-only official skill: Sandbox Scan finds nothing to run (verdict: inconclusive coverage)."),
    _remote("anthropic-claude-api", "anthropics/skills - claude-api", "Benign public controls",
            _ANTHROPIC + "claude-api", "benign",
            "Docs that warn against curl|sh and prompt injection: findings are downgraded to LOW."),
]

_BY_ID = {item["id"]: item for item in SAMPLES}


def get(sample_id: str) -> dict[str, Any] | None:
    return _BY_ID.get(sample_id)


def resolve_source(sample_id: str) -> str:
    """Return the scan source (local path or URL) for a sample id; raises KeyError if unknown."""
    item = _BY_ID[sample_id]
    if item["kind"] == "local":
        path = SAMPLES_DIR.parent / item["path"]
        if not path.is_dir():
            raise KeyError(f"Sample directory missing: {item['path']}")
        return str(path)
    return item["url"]


def public_listing() -> list[dict[str, Any]]:
    return [{key: value for key, value in item.items() if key != "path"} for item in SAMPLES]
