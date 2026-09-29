# AgentGuard scanner testing protocol

Status: pre-orchestration validation

This protocol validates the static behavior and machine-readable contracts of Cisco Skill Scanner, NVIDIA SkillSpector, and the AgentGuard custom rules. SkillWard is a design reference only and must not be executed as a scanner.

## Safety boundary

- Run this work on a disposable Kali VM or isolated test machine.
- Do not execute any scanned skill, script, package installer, post-install hook, or agent workflow.
- Do not run the benchmark dynamic executor yet. The benchmark warns that its host-auth executor is instrumentation, not a strong isolation boundary.
- Use static-only options and synthetic fixtures first.
- Do not upload files to VirusTotal, Cisco AI Defense, an LLM provider, or any remote service.
- Record outbound dependency lookups. NVIDIA may query OSV.dev even with `--no-llm`; use an offline/network policy if required.
- Keep benchmark data and scanner checkouts outside the public AgentGuard repository. They are local research inputs, not application dependencies.

## Benchmark facts

Repository: https://github.com/protectskills/MaliciousAgentSkillsBench
Pinned research revision: `f7d28b1a9de4eb33d552529cf79d1065d765f6c3`
License: MIT

The released repository contains metadata, not a complete local package corpus:

- `data/malicious_skills.csv`: 157 confirmed malicious labels with pattern and severity metadata.
- `data/skills_dataset.csv`: 98,380 mutually exclusive labels: 94,093 safe, 4,130 suspicious, and 157 malicious.
- Malicious download URLs are redacted. Do not attempt to reconstruct or bypass those redactions.
- The benchmark's scanner source is under `code/scanner/skill-security-scan`.

Therefore, benchmark evaluation has two parts:

1. Contract tests on controlled fixtures and any legally approved public samples.
2. Label-aware evaluation only for samples whose source package can be obtained lawfully and safely.

A CSV row is not itself a skill package and must never be treated as a scan input.

## Required environment capture

The tester must save this information in `artifacts/environment.json`:

- OS and kernel
- Python version
- Python environment path
- Git version
- Docker version, if available
- Cisco package/version and source commit
- NVIDIA package/version and source commit
- AgentGuard commit
- benchmark commit
- relevant command paths
- whether outbound HTTPS is enabled
- whether LLM, VirusTotal, AI Defense, and runtime execution are disabled

Never include API keys, tokens, `.env` files, or credential contents.

## Tool installation

Use separate virtual environments to prevent dependency conflicts.

### Cisco

Install the pinned source checkout or a pinned release in its own environment. Verify:

```bash
python --version
skill-scanner --help
skill-scanner list-analyzers
skill-scanner validate-rules
```

Record the exact installation command and `skill-scanner --version` output. Do not enable `--use-llm`, `--use-aidefense`, `--use-virustotal`, or upload modes.

### NVIDIA

Use Python 3.12 or newer, below the version ceiling declared by the pinned checkout, in a separate environment:

```bash
python --version
skillspector --version
skillspector scan --help
```

Do not configure an LLM provider. Always pass `--no-llm`.

### Benchmark scanner

This is a reference baseline, not an AgentGuard dependency. Its source CLI is:

```bash
cd code/scanner/skill-security-scan
python -m src.cli scan <fixture> --format json --output <report.json>
```

The benchmark scanner's JSON reporter projects native fields such as `risk_score`, `risk_level`, `summary`, `issues`, `total_issues`, and `recommendation`. Preserve the full native report as evidence.

## Fixture corpus

Build a controlled corpus under a disposable directory. Do not put it in Git.

| Fixture | Expected purpose | Required signals |
|---|---|---|
| `safe-minimal` | False-positive control | Valid `SKILL.md`, harmless instructions, no scripts |
| `prompt-injection` | Instruction detection | Hidden HTML/markdown comment, override language, invisible Unicode variant |
| `credential-access` | Sensitive source detection | Static references to env secrets and SSH/cloud credential paths; no execution |
| `external-transmission` | Network sink detection | Static HTTP POST/request to a documentation domain; no execution |
| `code-execution` | Dangerous API detection | Static `eval`, `exec`, `subprocess`, shell, and dynamic import references |
| `supply-chain` | Dependency checks | Unpinned dependency, remote installer text, package source redirection |
| `mcp-metadata` | MCP-only checks | Tool description injection, Unicode deception, wildcard/missing permissions |
| `combined-chain` | Correlation/taint check | Credential source plus network sink plus obfuscation in one static file |
| `malformed` | Error contract | Missing/invalid frontmatter and invalid Python; scanner must fail or report explicitly, never silently pass |
| `oversized` | Resource bounds | Generated large text file within the scanner's documented limits and one over-limit case if safe to create |

Use inert strings and documentation domains such as `example.invalid`. Do not use real secrets, real attacker infrastructure, live malware, or runnable exfiltration code.

Each fixture must have a manifest:

```json
{
  "fixture_id": "combined-chain",
  "label": "synthetic-threat",
  "expected_categories": ["credential_access", "external_transmission"],
  "expected_min_severity": "high",
  "execution_allowed": false
}
```

## Test matrix

Run each fixture through each scanner in each applicable mode:

| Test | Cisco | NVIDIA | AgentGuard | Purpose |
|---|---:|---:|---:|---|
| valid safe fixture | yes | yes | yes | baseline false positives |
| each single-signal fixture | yes | yes | yes | rule coverage |
| combined-chain fixture | yes with behavioral | yes static | yes | correlation and gap detection |
| malformed fixture | yes with lenient/off | yes | yes | error and partial-analysis behavior |
| custom rule/config fixture | custom rules/policy | extra YARA/baseline if available | native rule profile | configuration semantics |
| repeated identical scan | yes | yes | yes | determinism and stable fingerprints |
| report to stdout | yes | yes | yes | parser behavior |
| report to file | yes | yes | yes | artifact behavior |
| severity gate | `--fail-on-severity high` | read exit code and recommendation | configured gate | exit-code contract |

### Cisco command profile

```bash
skill-scanner scan <fixture> \
  --use-behavioral \
  --format json \
  --output artifacts/cisco/<fixture>.json
```

Also record `--format sarif` for one safe and one combined fixture. Test `--lenient` only against the malformed fixture. Keep OSV, VirusTotal, AI Defense, LLM, and meta analyzers disabled.

Capture:

- exit code
- stdout and stderr separately
- exact argument list
- JSON parse success
- `findings`, `findings_count`, `max_severity`, `is_safe`, `analyzers_used`
- every native finding field, including metadata and line location
- whether findings are stable across two identical runs

### NVIDIA command profile

```bash
skillspector scan <fixture> \
  --no-llm \
  --format json \
  --output artifacts/nvidia/<fixture>.json
```

Also record SARIF for one safe and one combined fixture. Test a baseline only after the raw contract is captured; do not use suppression to hide findings during coverage measurement.

Capture:

- exit code: `0`, `1`, or `2`
- JSON parse success
- `skill`, `risk_assessment`, `components`, `issues`, and `metadata`
- `metadata.llm_requested`, analyzer completeness/ledger fields, and any OSV/offline indication
- native issue ID, category, severity, confidence, location, evidence, and message
- stable fingerprints across two identical runs

### AgentGuard command profile

Run the current native scanner with external adapters disabled while upstream contracts are being studied:

```bash
python main.py scan <fixture> --no-external --output artifacts/agentguard
```

Capture the normalized output and native rule IDs. Do not compare counts directly across tools; compare coverage by fixture signal, normalized category, severity, location, and evidence.

## Raw artifact layout

The tester must return a tar/zip archive with this shape, excluding secrets:

```text
artifacts/
  environment.json
  benchmark_revision.txt
  fixtures/
    <fixture>/manifest.json
  cisco/
    <fixture>.json
    <fixture>.stdout
    <fixture>.stderr
    <fixture>.meta.json
  nvidia/
    <fixture>.json
    <fixture>.stdout
    <fixture>.stderr
    <fixture>.meta.json
  agentguard/
    <fixture>.json
    <fixture>.meta.json
  comparison.json
  tester-notes.md
```

Each `*.meta.json` must include `tool`, `tool_version`, `source_commit`, `fixture_id`, `command` as an argument array, UTC start/end timestamps, duration, exit code, network mode, and parse status.

## Comparison output

`comparison.json` should contain one record per fixture and tool:

```json
{
  "fixture_id": "combined-chain",
  "tool": "cisco",
  "label": "synthetic-threat",
  "expected_signals": ["credential_access", "external_transmission"],
  "observed_findings": 3,
  "observed_categories": ["data_exfiltration", "command_injection"],
  "max_severity": "critical",
  "parse_ok": true,
  "exit_code": 1,
  "notes": "No code was executed"
}
```

Do not claim precision, recall, or benchmark accuracy from synthetic fixtures. Use them to validate plumbing, output mapping, deterministic behavior, and obvious coverage gaps. Label-aware metrics require a verified package corpus and a documented sampling method.

## Stop conditions

Stop and report instead of continuing if:

- a scanner attempts to execute a fixture;
- an LLM, cloud analyzer, VirusTotal upload, or runtime sandbox is enabled unexpectedly;
- a tool requests credentials or emits them;
- an archive extracts outside its designated directory;
- the scanner hangs or exceeds the configured timeout;
- a result cannot be tied to an exact tool version and commit.
