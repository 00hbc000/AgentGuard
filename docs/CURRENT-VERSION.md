# AgentGuard — Current Project Status

**Version:** 0.1.0 development version  
**Status:** Working prototype / active development  
**Purpose:** Scan AI Agent Skills and repositories for static and runtime security risks.

This document describes the current implementation. AgentGuard is functional for
local demonstrations and controlled Kali/Kubernetes testing, but it is not yet a
production security service. The architecture and UI will continue to change as
the project is hardened and evaluated.

## What AgentGuard does

AgentGuard accepts a local skill directory or a public GitHub, GitLab, or
Bitbucket URL. It materializes the input into a temporary workspace, performs
static analysis, optionally routes the result through a decision gate, and can
execute the skill inside an isolated Kubernetes sandbox.

The output is a normalized JSON report and, through the built-in dashboard, a
human-readable security report with findings, evidence, stages, and runtime
events.

## Current pipeline

### Stage 1 — Ingestion

- Accepts local directories and public repository URLs.
- Supports repository subpaths such as `/tree/main/skills/example`.
- Shallow-clones remote repositories.
- Applies input size and file-count limits.
- Records source, materialized path, and ingestion metadata.

### Stage 2 — Static analysis

AgentGuard runs native rules and optional external scanners against the same
materialized directory.

Native rules currently include:

| Rule | Meaning | Severity |
|---|---|---|
| `AG001` | Credential source reaches a network sink | HIGH |
| `AG002` | Obfuscation appears near credentials or a network sink | HIGH |
| `AG003` | `SKILL.md` frontmatter is malformed | MEDIUM |
| `AG004` | Configured external scanner reports no analyzed components | LOW |

Optional integrations:

- Cisco Skill Scanner
- NVIDIA SkillSpector

If an optional scanner is not installed, it is shown as **skipped**. This does
not invalidate a successful native scan. Actual scanner failures are reported
explicitly.

### Stage 3 — Decision gate

The gate decides whether ambiguous static evidence should be escalated to
runtime analysis.

- No findings or INFO-only findings: dynamic analysis is skipped.
- Obfuscation or MEDIUM evidence: dynamic analysis is requested.
- A single HIGH source: dynamic analysis is requested.
- Conclusive CRITICAL or independent HIGH evidence: dynamic analysis may stop
  at static analysis.

The CLI and dashboard can force dynamic analysis for demonstrations.

### Stage 4 — Dynamic sandbox

The dynamic runner:

1. Builds the sandbox and sink images.
2. Loads them into a local `kind` cluster.
3. Creates a non-root, restricted Kubernetes Pod.
4. Copies the skill into `/skill`.
5. Creates honeypot files.
6. Applies NetworkPolicies.
7. Proves that public internet access is blocked.
8. Proves that the controlled sink is reachable.
9. Runs the skill or Ollama-driven sandbox agent.
10. Collects sink events, agent events, traces, and Tetragon telemetry.
11. Converts proven honeypot exfiltration into a CRITICAL finding.
12. Deletes the sandbox Pod.

The sandbox supports:

- Ollama models reachable through an explicitly allowed CIDR.
- Allowlisted tools: `list_files`, `read_file`, `run_python`, and `done`.
- `/skill` path containment.
- Non-root execution.
- Dropped Linux capabilities.
- Read-only root filesystem.
- CPU, memory, storage, and execution-time limits.
- Tetragon monitoring when available, with a fallback tier when correlation is
  unavailable.

## Dashboard

The built-in web dashboard supports three scan modes:

### Quick Scan

Runs ingestion and static analysis. This is the fastest mode and is suitable
for a static repository review.

### Sandbox Scan

Runs static analysis and then executes the dynamic Kubernetes sandbox. The
dashboard uses asynchronous polling and displays queued, static, and sandbox
progress states.

### Deep Trace

Runs the full static plus forced dynamic path and displays the broadest
available runtime evidence.

## Demonstration commands

Run the test suite:

```bash
pytest -q
```

Run the controlled static malicious fixture:

```bash
python -m agentguard.cli scan \
  fixtures/combined-chain \
  --no-external \
  --output runs/professor-static
```

This fixture is expected to produce two native findings and a complete scan
status. A CLI exit code of `1` means the configured severity threshold was met;
it is not a scanner crash.

Run a public benign control:

```bash
python -m agentguard.cli scan \
  https://github.com/trailofbits/overtly-malicious-skills/tree/main/skills/csv-summarizer \
  --force-dynamic \
  --output runs/professor-demo
```

The CSV summarizer is a benign control. Zero findings is expected. The report
should still show the dynamic stage and its monitoring tier when the Kubernetes
environment is configured.

Start the dashboard:

```bash
python -m agentguard.cli web --host 0.0.0.0 --port 8080
```

Then open `http://<kali-ip>:8080` and select **Sandbox Scan**.

## Required dynamic environment

The real sandbox requires:

- Docker
- `kind`
- `kubectl`
- A NetworkPolicy-enforcing CNI such as Calico
- A running Kubernetes cluster
- The sandbox and sink images loaded into the cluster
- Optional Tetragon installation for kernel telemetry
- Ollama reachable from the cluster when Ollama mode is enabled

Typical Ollama configuration:

```bash
export AGENTGUARD_AGENT_MODE=ollama
export AGENTGUARD_OLLAMA_URL=http://172.19.0.1:11434
export AGENTGUARD_OLLAMA_MODEL=qwen2.5:1.5b
export AGENTGUARD_OLLAMA_CIDR=172.19.0.1/32
```

The URL and CIDR are environment-specific. They must be changed when the
cluster network differs.

## Current limitations

- The project is a development prototype, not a formally certified sandbox.
- External Cisco and NVIDIA scanners are optional and may be skipped.
- The dashboard currently keeps job state in memory; restarting the web process
  loses active jobs.
- Kubernetes image builds and sandbox startup can take several minutes.
- Tetragon may fall back when no matching event is captured for a short run.
- Small local models can hallucinate file paths or tool arguments. AgentGuard
  rejects unsafe or invalid actions and records the error.
- Dynamic behavior depends on the skill having an executable path or an
  Ollama agent being configured.
- The benchmark CSV files are datasets and indexes, not automatically
  executable skill packages.

## Verification statement

The current branch has been validated with the AgentGuard automated test suite
and controlled Kali demonstrations. Static findings, Kubernetes isolation,
Ollama connectivity, sandbox execution, and Tetragon collection have all been
tested in the development environment.

This is the current working version. The project is intentionally still being
changed: the next improvements are stronger runtime evidence, persistent job
storage, richer batch scanning, improved progress reporting, broader static
rules, and installation/documentation cleanup.
