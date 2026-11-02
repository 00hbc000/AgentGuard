# AgentGuard on Kali: Part 1 static scan, Part 2 dynamic sandbox

AgentGuard scans an AI agent skill in two stages:

| | Stage | Engines | Needs Kubernetes? |
|---|---|---|---|
| **Part 1** | **Static** (nothing is executed) | AgentGuard native rules AG001-AG011 **+ Cisco skill-scanner + NVIDIA SkillSpector** | no |
| **Part 2** | **Dynamic** (the skill runs in a locked-down kind pod with honeypots) | scripted harness, runtime guard, sink, canary tokens, optional Tetragon | yes |

Scan modes: **Quick** = Part 1 only. **Sandbox** = Part 1 + Part 2. **Deep** = Sandbox + an optional Ollama agent (off unless you opt in, see 2.6).

> **What was tested where.** Everything in Part 1 was run end to end in the development sandbox (CLI and dashboard,
> real Cisco 2.3.2 and real NVIDIA SkillSpector 2.12.0, live public malicious skills). The Python side of Part 2
> (harness, guard, canaries, sink, runner orchestration through a fake `kubectl`) is covered by automated tests.
> The development sandbox has no Docker/kind, so the **real-cluster** run in Part 2 is the one thing only your Kali can
> confirm. Part 2 says exactly what to send me if it fails.

---

## 0. Update the code and clean your shell (do this first)

```bash
cd ~/AgentGuard
git status --short                  # your local edit to docs/TEAM-HANDOFF.md is fine; nothing here touches it
git fetch origin arena/969bc471-agentguard
git switch test/sandbox-e2e         # the branch you already created
git merge --ff-only FETCH_HEAD      # fast-forward onto the new commit
git log --oneline -3
```

**Remove the Ollama variables from your shell.** An earlier handoff told you to export them. Current code ignores them
outside Deep mode, but a clean shell avoids confusion:

```bash
unset AGENTGUARD_AGENT_MODE AGENTGUARD_OLLAMA_URL AGENTGUARD_OLLAMA_CIDR AGENTGUARD_OLLAMA_MODEL
grep -n AGENTGUARD ~/.bashrc ~/.zshrc ~/.profile 2>/dev/null     # CHECK: if exports live here, delete those lines
env | grep AGENTGUARD                                            # expect: no output
```

---

# PART 1: Static scan (native + Cisco + NVIDIA)

## 1.1 Python environment and unit tests

```bash
cd ~/AgentGuard
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt pytest
python -m agentguard.tests.make_fixtures        # inert static fixtures (git-ignored)
pytest -q                                       # expect: 116 passed (about 15 s)
```

The suite is hermetic: it clears every `AGENTGUARD_*` variable itself, so your shell cannot change the result.
(It passed here with `AGENTGUARD_AGENT_MODE=ollama` and the other Ollama variables exported, to reproduce your setup.)

## 1.2 Install Cisco and NVIDIA

```bash
python -m pip install uv              # lets the installer fetch Python 3.13 for SkillSpector if your system lacks it
bash scripts/install_scanners.sh      # creates ~/.venvs/cisco and ~/.venvs/skillspector (takes a few minutes)
python -m agentguard.cli scanners
```

Expected:

```
cisco   AVAILABLE  venv /home/<you>/.venvs/cisco  -> .../skill-scanner scan
nvidia  AVAILABLE  venv /home/<you>/.venvs/skillspector  -> .../skillspector scan
```

No `export` is needed: AgentGuard looks in `~/.venvs/` (and `PATH`) by itself. The dashboard's readiness strip shows the same.

Why the script chooses its Python: SkillSpector needs Python 3.12-3.15 and depends on `yara-python`, which ships binary wheels
for 3.12 and 3.13 but **not 3.14** (your venv's Python). On 3.14 pip would compile it from source, which needs
`sudo apt install -y build-essential python3-dev libssl-dev` and may still fail. So the script prefers 3.13/3.12 and uses `uv`
to download one if needed. I verified the script here with Python 3.11 (Cisco) and 3.12 (NVIDIA, installed straight from
`git+https://github.com/NVIDIA/SkillSpector.git`). The `uv`-downloads-3.13 path could not be exercised here (my sandbox blocks
that download host). If it fails, tell me the last 15 lines of output, or point it at any 3.12/3.13 interpreter:
`AGENTGUARD_SCANNER_PYTHON=/usr/bin/python3.13 bash scripts/install_scanners.sh nvidia`.

Not installed? That is not an error: a missing scanner shows as `skipped` and the native rules still run.

## 1.3 CLI: all three engines on a fixture

```bash
python -m agentguard.cli scan fixtures/combined-chain --mode quick --output runs/static
echo "exit=$?"
```

Observed here: `findings: 5`, `scan_status: complete`, `verdict: malicious`, **exit 1** (exit 1 = findings, which is normal).
Per engine: cisco 1, nvidia 2, agentguard 2. Counts can differ by a finding or two with other scanner versions;
what matters is that `cisco` and `nvidia` both say `completed` in the report's `tool_runs`.

```bash
python3 - <<'EOF'
import json; d = json.load(open("runs/static/combined-chain.json"))
print({r["tool"]: r["status"] for r in d["tool_runs"]})
EOF
```

Expected: `{'cisco': 'completed', 'nvidia': 'completed'}`.

## 1.4 CLI: a live public malicious skill

```bash
python -m agentguard.cli scan https://github.com/trailofbits/overtly-malicious-skills/tree/main/skills/csv-summarizer \
    --mode quick --output runs/csv
```

Observed: about 15 s, `findings: 6`, `scan_status: complete`, verdict `high_risk`, exit 1.

This skill hides its payload behind 100,000 blank lines. SkillSpector's paragraph splitter is quadratic on that and would
time out, so AgentGuard detects the padding and gives NVIDIA a copy with the blank runs collapsed; the report says so
(`stages.nvidia.note`). The native rule AG006 inspects the original file.

## 1.5 Dashboard, Quick mode

```bash
python -m agentguard.cli web --host 0.0.0.0 --port 8080
```

Open `http://127.0.0.1:8080`. The readiness strip should show **Cisco scanner** and **NVIDIA scanner** as present
(docker/kind/kubectl chips only matter for Part 2).

1. Sample library -> `benign-csv-stats` -> **Quick Scan**. Verdict `NO FINDINGS`.
2. Sample library -> `runtime-env-dump` -> Quick Scan. Verdict `HIGH RISK`. The timeline shows
   `Running external scanner: cisco`, `... nvidia`, `... native rules`; the report lists findings tagged cisco / nvidia / agentguard.
3. **Batch** tab -> *Add all malicious samples* + *Add all benign controls* -> Quick -> Run (about 7 minutes with both scanners).

Observed result of the full 25-sample batch (all 25 scans completed, no scanner failures):

| Outcome | Count | Which |
|---|---|---|
| detected (malicious sample flagged) | **20 of 20** | every Trail of Bits, agent-guard-corpus, Cisco and runtime fixture, including `runtime-exfil-evasive` (which the native rules alone miss) |
| clean | 3 | `benign-csv-stats`, `cisco-simple-math`, `anthropic-brand-guidelines` |
| false positive | 2 | `anthropic-skill-creator`, `anthropic-claude-api`: both `HIGH RISK` |

Those two false positives are real opinions of the external engines on large benign skills (Cisco rates a CRITICAL on both;
NVIDIA reports 9 and 173 issues). They are labelled `HIGH RISK - CRITICAL from one engine` with that reason, never `malicious`:
**`malicious` requires runtime proof or CRITICAL findings from at least two engines.** That is why Part 2 exists: a
static flag is a reason to run the sandbox, not a conviction.

Timing: Cisco takes 7-20 s per skill, NVIDIA 5-35 s, but NVIDIA needs about 4.5 minutes for the 96-file `claude-api` skill
(timeout is 10 minutes; change with `AGENTGUARD_NVIDIA_TIMEOUT=<seconds>`).

---

# PART 2: Dynamic sandbox (Kubernetes)

## 2.1 Check the cluster (you already did; for reference)

```bash
docker version --format '{{.Server.Version}}'; kind version; kubectl version --client
kubectl get nodes                                         # a Ready node
kubectl -n kube-system get pods -l k8s-app=calico-node    # Running: NetworkPolicy is enforced
```

Your last output showed docker 28.5.2, kind v0.33.0, kubectl v1.36.4, cluster `agentguard` Ready, calico-node Running. The first
Sandbox Scan also proved isolation live (public internet blocked, sink reachable): AgentGuard refuses to run a skill if that
proof fails. A cluster needs a CNI that enforces NetworkPolicy; the usual recipe is kind with `disableDefaultCNI: true` plus Calico
(https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind).

## 2.2 Build the images (already done once; re-run after code changes under `sandbox/`)

```bash
python -m agentguard.cli prepare-sandbox       # prints the image tag (yours was 6c954ec4fd6f); unchanged code reuses the images
```

## 2.3 What the dynamic stage does

1. Starts a pod: read-only root, non-root, all capabilities dropped, no service-account token, egress only to the sink + cluster DNS.
2. Proves the isolation (three network probes). If any probe says "reachable from the internet", the scan stops.
3. Plants honeypots: fake `~/.aws/credentials`, `.ssh` key, `.env`, and canary environment variables. Each canary is unique per scan
   (`AGCANARY-<hex>-<NAME>`).
4. Runs the skill's entrypoint with the **scripted harness** (always; deterministic; no LLM), with a Python audit guard and `strace`.
5. A canary seen **in the sink's request log** is the proof of exfiltration -> CRITICAL `DYN_HONEYPOT_EXFIL` -> verdict `MALICIOUS`.
   Attempts to reach external hosts are HIGH `DYN_EXFIL_ATTEMPT` (blocked by policy, so not "proven").
6. Always deletes the pod. A sandbox that ran no commands gives `INCONCLUSIVE`, never "clean".

## 2.4 Acceptance check on the real cluster

```bash
python scripts/verify_sandbox.py
```

It runs five controlled samples through a real Sandbox Scan:

| Sample | Must produce |
|---|---|
| `benign-csv-stats` | ran 1 command, no findings, verdict `no_findings` |
| `runtime-exfil-sink` | CRITICAL `DYN_HONEYPOT_EXFIL` |
| `runtime-exfil-evasive` | CRITICAL `DYN_HONEYPOT_EXFIL` |
| `runtime-exfil-external` | HIGH `DYN_EXFIL_ATTEMPT`, never CRITICAL |
| `runtime-env-dump` | HIGH `DYN_ENV_EXPOSED` |

Last line should be `ALL CHECKS PASSED`. The same expectations pass here with the real in-pod harness (directly, and for the benign and evasive samples through the
full runner behind a fake `kubectl`, including with `AGENTGUARD_AGENT_MODE=ollama` exported). The earlier failure on your machine was that exported variable replacing
the scripted harness with the Ollama agent, which is fixed.

**If it fails, send me** the printed summary plus these two outputs (they show whether `strace`/the guard work in your pod):

```bash
kubectl -n agentguard-sandbox get pods,networkpolicy
kubectl -n agentguard-sandbox logs deploy/agentguard-sink --tail=40
```

Likely messages: `isolation proof failed` -> the CNI does not enforce NetworkPolicy (Calico). `trace_available: false` -> `strace` is not
allowed in the pod; scans still work through the guard and sink (only non-Python syscall evidence is lost). A hang is bounded: the
skill exec is capped at 240 s (`AGENTGUARD_DYNAMIC_TIMEOUT`); stray pods: `kubectl -n agentguard-sandbox delete pod --all`.

## 2.5 Dashboard, Sandbox mode (static first, then dynamic)

Restart the dashboard in the same shell (it must be the shell without the Ollama variables), then:

1. `benign-csv-stats` -> **Sandbox Scan**. Timeline: ingestion, static (cisco, nvidia, native), gate, sandbox. Verdict `NO FINDINGS`, runtime evidence shows 1 command run.
2. `runtime-exfil-evasive` -> Quick: static engines flag it (Cisco and NVIDIA catch it; the native rules alone do not) -> then **Sandbox Scan**:
   verdict **MALICIOUS - exfiltration proven at runtime**, CRITICAL `DYN_HONEYPOT_EXFIL`, and *Sink events* lists the canary names the sink received.
3. `runtime-exfil-sink`, `runtime-exfil-external`, `runtime-env-dump` as in the table above.
4. Press **Cancel** during a Sandbox Scan: the pod disappears (`kubectl -n agentguard-sandbox get pods`).
5. History tab: every run, with JSON and HTML downloads. Stop and restart the dashboard: history survives (`runs/web/`).

## 2.6 Deep mode and the optional Ollama agent

Deep = the Sandbox scan above **plus** an LLM agent that explores the skill after the scripted run. It is off unless you opt in
before starting the dashboard:

```bash
export AGENTGUARD_AGENT_MODE=ollama AGENTGUARD_OLLAMA_URL=http://172.19.0.1:11434 \
       AGENTGUARD_OLLAMA_CIDR=172.19.0.1/32 AGENTGUARD_OLLAMA_MODEL=qwen2.5:1.5b
```

Rules: it never replaces the scripted harness; it only runs in **Deep** mode; it is time-bounded (`AGENTGUARD_AGENT_TIMEOUT`, default
180 s); and if Ollama is unreachable the scan still completes, with `agent_errors` in the coverage and `mode: scripted+ollama_agent`.
Sandbox mode ignores these variables entirely. Unset them again when you are done.

## 2.7 Known limits

- The runtime guard covers Python only; other languages are seen through `strace` and the sink.
- Events inside the pod can be tampered with by hostile code; only sink evidence is authoritative.
- Cluster DNS is allowed, so DNS-tunnel exfiltration would not be seen by the sink.
- Only one Sandbox Scan runs at a time (the dashboard queues the rest).
- Static analysis cannot find attacks that live only in prose; use Deep/LLM review for those.

## Safety rules this setup keeps

- Skill code runs only in the pod. Remote skills are downloaded with `git` (hooks off, no submodules, symlinks removed) and only read as text by the host.
- The dashboard accepts public GitHub/GitLab/Bitbucket URLs and library samples only, never local paths.
- `runs/`, `fixtures/` and reports are git-ignored; do not commit them, and keep real credentials away from this setup.
