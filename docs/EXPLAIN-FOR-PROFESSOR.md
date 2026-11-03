# AgentGuard explained: tools, pipeline, and the dynamic stage in detail

## 1. The problem and the idea

An **agent skill** is a folder (`SKILL.md` instructions + optional scripts) that an AI agent loads to gain a capability. A malicious
skill can steal credentials, hide instructions for the model, or run code on the user's machine. AgentGuard decides whether a skill
is safe to install, in two stages:

> **Static analysis finds suspicion. Dynamic analysis produces proof.**

Static analysis reads the files without executing anything: fast, but it can be fooled by obfuscation or code that builds its payload
at runtime. Dynamic analysis runs the skill inside a locked-down Kubernetes pod stuffed with fake secrets and watches what it does:
slower, but it can *prove* misbehaviour.

## 2. The pipeline end to end

```
 skill (GitHub URL, sample, or folder)
        |
 [0] INGESTION      git clone (sparse, hooks off, no submodules), symlinks removed, nothing executed
        |
 [1] STATIC STAGE   (Quick mode stops here)
        |-- AgentGuard native rules AG001-AG011
        |-- Cisco skill-scanner         --> findings normalised to one schema
        |-- NVIDIA SkillSpector         --> findings normalised to one schema
        |
 [2] DECISION GATE  clean-looking skills that ship scripts are still sent to the sandbox
        |
 [3] DYNAMIC STAGE  (Sandbox / Deep mode)   Kubernetes (kind) + Calico + sink + honeypots + guard + strace + Tetragon
        |
 [4] VERDICT        malicious / high_risk / suspicious / low_risk / no_findings / inconclusive  + evidence + coverage gaps
        |
 report (JSON + HTML) in the dashboard, with History, batch scanning and downloads
```

**Scan modes:** *Quick* = stages 0-1. *Sandbox* = 0-4. *Deep* = Sandbox plus an optional Ollama LLM agent (off by default).

## 3. Every tool, and why it is there

| Tool | What it is | Role in AgentGuard |
|---|---|---|
| **Python 3** | language of the whole backend | orchestration, rules, dashboard server, in-pod harness |
| **git** | version control | downloads skills safely (sparse checkout, hooks disabled, symlinks stripped) |
| **AgentGuard native rules** (AG001-AG011) | our own regex/structure rules | credential->network chains, obfuscation, hidden content, disguised archives, `curl\|sh`, prompt injection, decode-and-exec, `/etc/shadow`, env dumps |
| **Cisco skill-scanner** | open-source scanner from Cisco AI Defense (`pip install cisco-ai-skill-scanner`) | static + behavioural analysis, maps to OWASP/MITRE categories |
| **NVIDIA SkillSpector** | NVIDIA's scanner (71 patterns, taint tracking, YARA; run with `--no-llm`) | independent second opinion; needs Python 3.12+ |
| **Decision gate** (`gate.py`) | small Python module | decides whether the sandbox is needed |
| **Docker** | container engine | builds the sandbox and sink images; hosts the kind node |
| **kind** | "Kubernetes in Docker" | a real, throw-away Kubernetes cluster on one machine |
| **kubectl** | Kubernetes CLI | AgentGuard drives the cluster with it: create pod, copy skill, exec commands, read logs, delete pod |
| **Calico** | Kubernetes network plugin (CNI) | *enforces* NetworkPolicy; without it the isolation would be only on paper |
| **NetworkPolicy** (`k8s/network-policy.yaml`) | Kubernetes firewall rule | sandbox pod may talk **only** to the sink (TCP 8080) and cluster DNS |
| **Sink server** (`sandbox/sink_server.py`) | tiny HTTP server in its own pod | the only reachable destination; logs every request (path, headers, body) and checks it for canaries |
| **Honeypots + canaries** (`sandbox/canary.py`, `execution.py`) | fake secrets | bait whose appearance in traffic is proof of theft |
| **Runtime guard** (`sandbox/guard/sitecustomize.py`) | Python *audit hook* | records file reads, DNS, connects, HTTP requests, process spawns, `exec`/`compile` inside the skill |
| **strace** | Linux syscall tracer | sees file/network syscalls of non-Python code too |
| **Tetragon** (Cilium) | eBPF kernel-level observability | independent, kernel-side process/network/file events for the pod ("monitoring tier: tetragon") |
| **Ollama** (optional) | local LLM server | Deep mode only: an agent explores the skill after the scripted run |
| **Dashboard** (`web.py`, stdlib HTTP server + vanilla JS) | web UI | Quick/Sandbox/Deep scans, live stage timeline, cancel, History, Batch, report download |
| **JobStore** (`jobs.py`) | disk-backed job queue | durable jobs/batches, one sandbox scan at a time, survives restarts |
| **pytest** | test framework | 117 automated tests, including a fake-`kubectl` test of the whole runner |

## 4. Static stage in detail

- **Native rules.** AG001 credential source reaching a network sink; AG002 obfuscation; AG003 malformed front matter; AG004 incomplete
  scan; AG005 environment dump; AG006 hidden content (e.g. payload hidden behind 100,000 blank lines, invisible tag characters);
  AG007 disguised archives/bytecode; AG008 `curl|sh` and registry redirects; AG009 prompt injection in hidden comments; AG010 decode-and-exec;
  AG011 sensitive files (`/etc/shadow`). Each finding has rule id, severity, message, file and line.
- **Cisco and NVIDIA** run as external commands. Their JSON is parsed by *adapters* into AgentGuard's single **normalised finding schema**
  (tool, rule, category, severity, location, evidence, remediation), so reports show all engines side by side. A missing scanner is
  `skipped`; a crashing or timed-out scanner is reported `failed`, never hidden.
- **Real-world handling.** SkillSpector is quadratic on huge blank-line padding (a known trick); AgentGuard detects it and gives NVIDIA a
  collapsed copy, and says so in the report. Native rule AG006 still inspects the original.
- **Verdict rule.** `malicious` needs runtime proof *or* CRITICAL from at least two engines. One engine's lone CRITICAL is `high_risk`
  with that stated, because external scanners are noisy (measured: 2 of 5 benign public skills got flagged).

## 5. Dynamic stage in detail (what happens during a Sandbox Scan)

**Infrastructure (set up once):** a kind cluster `agentguard` with Calico. Namespace `agentguard-sandbox` holds a **sink** Deployment+Service
and the **NetworkPolicy**. Two images are built by Docker and loaded into kind: `agentguard-sandbox` (Python 3.14 + strace + our harness) and
`agentguard-sink`. The image tag is a hash of the `sandbox/` code, so unchanged code reuses images.

**Per scan, step by step:**

1. **Preflight.** Checks docker/kind/kubectl, cluster reachable, images present, applies namespace, sink and policy, waits for the sink.
2. **Create the sandbox pod.** Hardened: read-only root filesystem, non-root user (uid 1000), *all* Linux capabilities dropped, no privilege
   escalation, default seccomp profile, **no service-account token**, CPU/memory/disk limits, 300 s hard deadline, 1 s termination grace.
   Writable space is only three scratch volumes (`/tmp`, `/skill`, `/honeypots`). Each scan gets a fresh 32-hex **scan token**.
3. **Copy the skill in.** Host `tar` streams files into the pod (skipping symlinks and `.git`). The host never executes skill code.
4. **Prove isolation before trusting it.** Three probes from inside the pod: public internet (1.1.1.1:80) must be **blocked**; the sink must be
   **reachable**; external DNS (1.1.1.1:53) must be **blocked**. If any proof fails, the scan aborts with "isolation proof failed" and the skill
   is never run. (This is what makes "sandboxed" a tested fact, not an assumption.)
5. **Plant honeypots** (`--phase prepare`): fake `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.env`, an extra credentials file, and environment variables
   `AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, OPENAI_API_KEY, ANTHROPIC_API_KEY, NPM_TOKEN, DATABASE_URL`. Every value is a **canary**:
   `AGCANARY-<scan token>-<NAME>`. The skill sees a normal-looking home directory.
6. **Execute the skill** (`--phase execute`, the deterministic **scripted harness**, no LLM): it discovers commands from `SKILL.md`/`README.md` usage lines
   (python/bash/node + script inside the skill) and falls back to scripts it finds; fills arguments with generated sample files; runs each command with
   a timeout, the decoy `HOME`, the canary environment, the Python audit guard loaded automatically (via `PYTHONPATH`/`sitecustomize`), and `strace`.
7. **Collect evidence from four independent sources:**
   - **Sink log** (`kubectl logs`): every request that actually left the pod; the sink scans path, headers and body for canaries, also in
     URL-encoded, base64, urlsafe-base64, hex and double-wrapped forms. **This is the authoritative proof.**
   - **Guard events** (inside the pod): honeypot reads, DNS lookups, connect attempts, HTTP requests/payloads, process spawns, dynamic `exec`/`compile`.
     This also shows traffic the NetworkPolicy *dropped*, which the sink can never see.
   - **strace** log: file and network syscalls, including non-Python code.
   - **Tetragon** eBPF events for that pod (if Tetragon is installed): kernel-side, outside the skill's control.
8. **Derive findings** (`collector.py`):

   | Rule | Severity | Meaning |
   |---|---|---|
   | `DYN_HONEYPOT_EXFIL` | **CRITICAL** | a canary of *this* scan arrived at the sink: **proven exfiltration** |
   | `DYN_EXFIL_ATTEMPT` | HIGH | tried to send canary data to an external host (blocked, so not "proven") |
   | `DYN_ENV_EXPOSED` | HIGH | printed canary secrets to its output |
   | `DYN_HONEYPOT_READ` | MEDIUM (HIGH if it also went out) | read fake credential files |
   | `DYN_EGRESS_ATTEMPT` | MEDIUM external / LOW internal | tried to open outside connections |
   | `DYN_DYNAMIC_EXEC` | MEDIUM | executed dynamically built code |

9. **Always clean up.** The pod is deleted in a `finally` block, even after errors or timeouts. Coverage is recorded
   (commands run/failed/timed out, guard enabled, strace available, monitoring tier). A scan where **zero commands ran** is **inconclusive**, never "clean".

**Design choices to mention:**
- *Proof, not heuristics:* the per-scan token means a match cannot be a coincidence or leftover from another scan.
- *Defence in depth:* network policy blocks, guard + strace + Tetragon observe, sink proves. Different layers fail differently.
- *Honest reporting:* `no_findings` is never called "safe"; gaps (no entrypoint, sandbox failed, gate skipped) are listed in the verdict.
- *Deterministic by default:* no LLM, no API keys, same result each run. Deep mode adds an optional Ollama agent after the scripted run,
  time-bounded, and its failure cannot fail the scan.

## 6. Evidence from our own runs

- Real kind cluster (Calico + Tetragon): `verify_sandbox.py` **ALL CHECKS PASSED**: benign skill `no_findings`; two exfiltration skills CRITICAL
  `DYN_HONEYPOT_EXFIL` (verdict `malicious`); external-attempt skill HIGH; env-dump skill HIGH. All four monitors active.
- Quick-mode batch of 25 samples with all three engines: 20 of 20 malicious flagged, 3 benign clean, 2 benign large skills flagged `high_risk`.
- 117 automated tests; the sandbox harness is also tested locally and through a fake cluster.
- Sources used for test material: Trail of Bits `overtly-malicious-skills`, `agent-guard-corpus`, Cisco `skill-scanner` eval skills (malicious);
  Anthropic `skills` (benign controls). The approach is inspired by **SkillWard** (static -> LLM -> sandbox with honeypots and a runtime guard);
  differences: Kubernetes with NetworkPolicy instead of plain Docker, canary-based *proof*, and no LLM triage stage.

## 7. Limitations (say these before the professor asks)

- The in-pod guard covers **Python**; other languages rely on strace/Tetragon and the sink.
- Events recorded *inside* the pod can be tampered with by hostile code; only sink and kernel-level (Tetragon) evidence are authoritative.
- Cluster DNS is allowed, so DNS-tunnelling exfiltration is not seen by the sink.
- A skill that detects the sandbox, waits out the timeout, or needs real credentials/APIs to reach its payload can pass. No findings is not a guarantee.
- Static tools cannot catch attacks that live only in prose (prompt injection without markers); an LLM or human review is needed.
- One sandbox scan at a time; static scanners are noisy on large benign skills.
