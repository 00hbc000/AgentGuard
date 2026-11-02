# AgentGuard — Project Handoff

> **Correction (added later).** `csv-summarizer` from `trailofbits/overtly-malicious-skills` is **malicious** (it dumps
> `os.environ` hidden behind ~100,000 blank lines), so it is not a benign control. AgentGuard now flags it (AG005 + AG006).
> Use `samples/benign-csv-stats`, `anthropics/skills` entries or Cisco's `safe-skills/simple-math` as controls; all are in the
> dashboard sample library. Current setup instructions: [KALI-QUICKSTART.md](KALI-QUICKSTART.md).


**Project:** AgentGuard  
**Repository:** `00hbc000/AgentGuard`  
**Branch:** `feature/dynamic-analysis`  
**Current version:** `0.1.0 development prototype`  
**Status:** Functional demonstration build; active development continues.

## 1. Objective

AgentGuard is a security scanner for AI Agent Skills and skill repositories.
Its objective is to identify malicious or risky behavior before a skill is
installed or executed.

The target workflow is:

1. Accept a local skill directory or public repository URL.
2. Materialize and validate the input safely.
3. Run static analysis and normalize findings.
4. Decide whether ambiguous results require runtime verification.
5. Execute suspicious skills inside an isolated Kubernetes sandbox.
6. Collect runtime evidence from sink events, traces, agent events, and
   Tetragon when available.
7. Produce an evidence-rich report and a clear safety verdict.

The project is intended to provide a professor-ready demonstration of both
static and dynamic security analysis. It is not yet a production-certified
security platform.

## 2. Current architecture

### Ingestion

Implemented in `agentguard/ingest.py`.

- Accepts local directories and public GitHub, GitLab, and Bitbucket URLs.
- Supports repository subpaths such as `/tree/main/skills/example`.
- Clones remote sources into temporary workspaces.
- Applies size and file limits.
- Records ingestion metadata.

### Static analysis

Implemented in `agentguard/custom_rules.py` and `agentguard/orchestrator.py`.

Native rules:

| Rule | Description | Severity |
|---|---|---|
| `AG001` | Credential source reaches a network sink | HIGH |
| `AG002` | Obfuscation near credentials or a network sink | HIGH |
| `AG003` | Malformed `SKILL.md` frontmatter | MEDIUM |
| `AG004` | External scanner reports no analyzed components | LOW |

Optional adapters are available for:

- Cisco Skill Scanner
- NVIDIA SkillSpector

Missing optional scanners are reported as `skipped` and do not invalidate a
successful native scan. Actual scanner failures remain visible.

### Decision gate

Implemented in `agentguard/gate.py`.

The gate escalates ambiguous static evidence to dynamic analysis. The CLI and
dashboard can also force dynamic analysis for demonstrations.

### Dynamic sandbox

Implemented in `agentguard/dynamic/` and `sandbox/`.

The sandbox:

- Builds and loads dedicated Docker images into `kind`.
- Runs as a non-root Kubernetes Pod.
- Uses restrictive security contexts and resource limits.
- Mounts the skill under `/skill`.
- Creates honeypot files.
- Applies NetworkPolicies.
- Blocks public internet and external DNS.
- Allows access to the controlled sink.
- Supports Ollama-driven execution.
- Allows only `list_files`, `read_file`, `run_python`, and `done`.
- Enforces `/skill` path containment.
- Collects sink, agent, trace, and Tetragon events.
- Converts proven honeypot exfiltration into a CRITICAL finding.
- Deletes the sandbox Pod after execution.

### Dashboard

Implemented in `agentguard/web.py`.

Available modes:

- **Quick Scan:** ingestion plus static analysis.
- **Sandbox Scan:** static analysis plus Kubernetes runtime analysis.
- **Deep Trace:** forced static plus dynamic analysis with runtime evidence.

The dashboard submits scans asynchronously through `/api/jobs` and polls for
progress and results.

## 3. Verified behavior

Automated tests currently pass locally.

Verify with:

```bash
pytest -q
```

The controlled static fixture produces two findings:

```bash
python -m agentguard.cli scan \
  fixtures/combined-chain \
  --no-external \
  --output runs/professor-static
```

Expected result:

```text
findings: 2
scan_status: complete
```

The CLI may return exit code `1` for this fixture because its findings meet the
configured severity threshold. That is expected and does not indicate a crash.

The benign public control is:

```text
https://github.com/trailofbits/overtly-malicious-skills/tree/main/skills/csv-summarizer
```

It is expected to produce zero findings. It is useful for demonstrating that a
clean skill can pass static analysis while still going through the dynamic
pipeline.

## 4. Kali/Kubernetes setup

On Kali:

```bash
cd ~/AgentGuard
git pull
source .venv/bin/activate
./scripts/build_and_load.sh
```

For Ollama:

```bash
export AGENTGUARD_AGENT_MODE=ollama
export AGENTGUARD_OLLAMA_URL=http://172.19.0.1:11434
export AGENTGUARD_OLLAMA_MODEL=qwen2.5:1.5b
export AGENTGUARD_OLLAMA_CIDR=172.19.0.1/32
```

The URL and CIDR are environment-specific. Confirm that Ollama is reachable
from a sandbox Pod before scanning.

Start the dashboard:

```bash
python -m agentguard.cli web --host 0.0.0.0 --port 8080
```

Open `http://<kali-ip>:8080` and select **Sandbox Scan**.

Useful environment checks:

```bash
kubectl get nodes
kubectl -n kube-system get daemonset tetragon
kubectl -n agentguard-sandbox get networkpolicy
curl -fsS http://172.19.0.1:11434/api/tags
```

## 5. Immediate remaining work

Prioritize these items in order:

1. **Run a full end-to-end Sandbox Scan from the dashboard.**
   Confirm that the selected mode reaches the worker, progress is displayed,
   the sandbox completes, and the final report contains the dynamic stage.

2. **Improve dynamic progress reporting.**
   The current job state is in memory and exposes coarse phases. Add durable
   job storage or a persistent queue if scans must survive web-server restarts.

3. **Improve runtime evidence.**
   Make sink events, agent actions, execution errors, Tetragon events, and
   monitoring tier easy to distinguish in the UI.

4. **Test a controlled malicious dynamic fixture.**
   Demonstrate a honeypot read followed by a sink transmission and verify that
   the report contains a CRITICAL dynamic finding.

5. **Install optional external scanners only if required.**
   Configure real Cisco and NVIDIA executable paths and verify their adapters
   independently. Never commit credentials or local absolute paths.

6. **Add batch scanning.**
   Support multiple skills and aggregate results if the professor requires a
   SkillWard-style batch demonstration.

7. **Harden the dashboard.**
   Add clearer error states, cancellation, scan history, and report download.

## 6. Known limitations

- This is a development prototype, not a certified production sandbox.
- Optional Cisco/NVIDIA tools may be unavailable.
- Dashboard jobs are stored only in process memory.
- Docker image builds and Kubernetes startup can take several minutes.
- Tetragon may fall back when no matching event is captured.
- Small local models may hallucinate paths or tool arguments. Invalid actions
  are rejected and returned to the model for recovery.
- Dynamic execution depends on a valid entrypoint or configured Ollama agent.
- Benchmark CSV files are datasets, not executable skill packages.
- The repository may contain local changes in `docs/TEAM-HANDOFF.md`; preserve
  them unless the owner explicitly requests otherwise.

## 7. Files to understand first

- `agentguard/orchestrator.py` — main pipeline coordinator.
- `agentguard/ingest.py` — source validation and materialization.
- `agentguard/custom_rules.py` — native static rules.
- `agentguard/gate.py` — dynamic escalation logic.
- `agentguard/models.py` — `Finding`, `ToolRun`, and `ScanResult`.
- `agentguard/web.py` — dashboard and job API.
- `agentguard/dynamic/runner.py` — Kubernetes execution.
- `agentguard/dynamic/collector.py` — runtime event normalization.
- `sandbox/agent_executor.py` — Ollama tool loop and restrictions.
- `sandbox/run_skill.py` — sandbox entrypoint.
- `scripts/build_and_load.sh` — image build and `kind` loading.
- `scripts/kali_demo_verify.sh` — Kali environment verification.

## 8. Development rules

- Preserve the normalized finding schema.
- Do not weaken sandbox path, network, or tool restrictions.
- Do not execute untrusted skills outside the sandbox.
- Keep static and dynamic evidence separate and explicit.
- Do not hide scanner failures behind successful-looking results.
- Do not commit API keys, credentials, generated reports, or local environment
  files.
- Run focused tests after changes and the full suite before handoff.
- Preserve unrelated worktree changes.

## 9. Definition of done for the next phase

The next phase is complete when:

- A public benign skill can be submitted from the dashboard.
- Quick Scan visibly completes static analysis.
- Sandbox Scan visibly runs inside Kubernetes without blocking the browser.
- Dynamic runtime events appear in the report.
- A controlled malicious fixture produces visible static findings.
- A controlled runtime exfiltration produces a CRITICAL dynamic finding.
- The report clearly identifies the selected mode, stages, verdict, evidence,
  monitoring tier, and remediation.
- Automated tests pass.
