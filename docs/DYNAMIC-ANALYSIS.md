# How the Sandbox Scan produces evidence

## Pipeline

1. **Ingestion** downloads or copies the skill (never executes it): sparse checkout for `/tree/<ref>/<path>` URLs,
   hooks off, no submodules, symlinks removed, size and file limits.
2. **Static stage**: native rules AG001-AG011 plus optional Cisco/NVIDIA scanners.
3. **Decision gate**: Sandbox and Deep modes always continue. In gate-driven CLI mode (`--dynamic`) it escalates on
   MEDIUM/HIGH evidence, and also for a *clean* skill that ships scripts, because static analysis cannot prove those clean.
4. **Sandbox stage** (this document).
5. **Verdict** (`agentguard/verdict.py`) summarises the evidence and, importantly, the *gaps*.

## Inside the sandbox

`run_skill.py --phase prepare` plants **decoys** with a per-scan token: `~/.aws/credentials`, `~/.ssh/id_rsa`, `.env`,
`gh/hosts.yml`, `.git-credentials`, `.npmrc` and similar under `/honeypots/home`, plus canary **environment variables**
(`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, ...). Every value looks like `AGCANARY-<scan-token>-<NAME>`.

`run_skill.py --phase execute` then runs the commands documented in `SKILL.md` (or `--command` / `AGENTGUARD_ENTRYPOINT`) with:

- `HOME` set to the decoy home and the canary variables in the environment;
- a Python **audit hook** (`sandbox/guard/sitecustomize.py`) that records network requests, process spawns, file opens
  of decoys, dynamic `exec`, and checks outbound payloads for canaries (plain, URL-encoded, base64, hex);
- `strace` when the pod allows it (syscall-level view of decoy opens and connects, including non-Python code);
- a sample CSV/JSON/text file substituted for path placeholders in the documented command.

The **sink** (`sink_server.py`) is the only host the pod can reach besides cluster DNS. It logs every request and the
canaries found in it.

## Findings, and how much each proves

| Rule | Severity | Evidence | Proves |
|---|---|---|---|
| `DYN_HONEYPOT_EXFIL` | CRITICAL | a canary of **this** scan arrived at the sink | exfiltration actually happened (inside the sandbox) |
| `DYN_EXFIL_ATTEMPT` | HIGH | the guard saw a canary in an outbound request the sink never received | an attempt (the policy blocked delivery) |
| `DYN_ENV_EXPOSED` | HIGH | canaries printed to stdout/stderr | the skill dumps the environment (an agent would log it) |
| `DYN_HONEYPOT_READ` | MEDIUM, HIGH with outbound traffic | decoy opened | credential-hunting behaviour |
| `DYN_EGRESS_ATTEMPT` | MEDIUM external, LOW internal, HIGH after a decoy read | connect to a non-sink address | network intent |
| `DYN_DYNAMIC_EXEC` | MEDIUM | `exec`/`compile` of generated code directly from skill code | runtime-built code |

Only the sink is authoritative: it runs in a different pod, so skill code cannot edit what it logged. Events written
inside the skill pod (guard, strace, agent) could in principle be tampered with by a determined skill.

## Honest coverage

`dynamic.coverage` records `commands_run`, `entrypoint_found`, `trace_available`, `guard_enabled`. A skill with no runnable
entrypoint, or a failed sandbox, produces verdict **inconclusive**, never "clean".

## Public malicious skills in the sandbox

The five controlled samples in `samples/` are ours. To check the sandbox against skills we did not write, the library
has a group of 12 skills from [MalSkillBench](https://github.com/lxyeternal/MalSkillBench) (dataset label: malicious;
licence: academic research use, so they are **downloaded on demand and never vendored**). They were picked by reading
the code, not by AgentGuard's results: the Python entry point must use only the standard library (the pod has no pip, a
`requests` import would only prove an ImportError) and must run without arguments. Skills that need `requests`
(for example the Skill-Inject file-backup script) and skills whose payload is a shell command inside `SKILL.md`
(snyk `toxicskills-goof`) were left out for that reason.

| Skill | Behaviour (dataset) | Native rules | Cisco 2.3.2 |
|---|---|---|---|
| `data-exfiltration` | wild; packs `/etc/passwd` + `~/.ssh`, leaks via DNS-over-HTTPS | nothing | MEDIUM |
| `agentuity-cli-project-list` | wild; ngrok reverse shell, reads `id_rsa`, AWS creds | AG002 | HIGH |
| `gen-docs` | wild; C2 reverse shell + `~/.bashrc` persistence | nothing | HIGH |
| `docker-expert` | wild; reads `id_rsa`, docker config, env, metadata IP | nothing | LOW |
| `osprey-migrate` | wild; downloads a binary from a raw IP, `chmod`, `.bashrc` | nothing | MEDIUM |
| `crypto-analysis` | wild; downloader + persistence + reboot | nothing | CRITICAL |
| `write-issue__CI_B1` | generated; `/etc/passwd` to webhook.site | AG002 | HIGH |
| `docs-write__CI_B2` | generated; env + `id_rsa` + `.env` to burpcollaborator | AG001, AG005 | HIGH |
| `copilot__MIXED_B2` | generated; env + `id_rsa` to ngrok | AG001, AG005 | CRITICAL |
| `vector-index-tuning__CI_B3` | generated; fetches a payload and `exec()`s it | AG010 | CRITICAL |
| `base64-payload` | Cisco test skill; **limit case**, exec sits in a function nothing calls | AG008, AG010 | CRITICAL |
| `continuous-learning` | wild; real reverse shell, **limit case**, needs a config file the pod lacks | nothing | INFO |

The two static columns were observed in development (native rules and Cisco only; NVIDIA was not run there). They show
a real gap: the native rules have no reverse-shell, persistence or downloader rule, so 6 of the 12 are invisible to them,
and `continuous-learning` is practically invisible to every static engine we ran. That is the case for the sandbox.

**What the sandbox does with them is not recorded here**: this development environment has no Kubernetes, so none of
these skills were executed. Run them where the cluster is:

```bash
python scripts/eval_public_dynamic.py                 # static + sandbox for all 12 (about 10-20 minutes)
python scripts/eval_public_dynamic.py --no-external   # faster: native rules only
python scripts/eval_public_dynamic.py --only msb-gen-docs
```

It prints one row per skill (native/Cisco/NVIDIA maximum severity, sandbox findings, commands run/failed, verdict) and writes
`runs/public-dynamic/results.md`. It asserts nothing: a skill whose payload needs the real internet will show a blocked
connection attempt (`DYN_EXFIL_ATTEMPT`/`DYN_EGRESS_ATTEMPT`), not a `DYN_HONEYPOT_EXFIL` proof, because only the sink is
reachable. In the dashboard the batch page has an **Add public runtime samples** button. Expect the two limit cases to
come back with few or no runtime findings; if they do, that is the documented "needs a trigger" limit, not a bug.

## Known limits

- The runtime guard covers **Python** only; non-Python code is seen through `strace` (when allowed) and the sink.
- Cluster DNS is allowed, so DNS-based exfiltration is possible; the sink would not see it.
- Skills that behave differently when they detect a sandbox, wait out the time limit, or need real credentials/APIs to
  reach their payload can pass. Absence of findings is not a safety guarantee.
- Prose-only attacks (prompt injection) are static-stage findings; the sandbox does not run an LLM unless you opt in to the
  Ollama agent. The agent runs only in **Deep** mode (`AGENTGUARD_AGENT_MODE=ollama`), as a separate time-bounded phase *after*
  the scripted harness; it never replaces it, and its failure does not fail the scan. Sandbox mode ignores those variables.
- Tetragon (eBPF) evidence is used when the DaemonSet is present and events correlate to the pod; otherwise tier `fallback`.
- Verified in development without Kubernetes: the harness, guard, canaries, sink, collector, runner orchestration (via a fake
  `kubectl`). Verified only on a real cluster by `scripts/verify_sandbox.py`: NetworkPolicy enforcement, `strace` under the pod's
  security context, Tetragon.

## Differences from SkillWard

SkillWard (Apache-2.0) runs an LLM agent inside a Docker container and adds an LLM triage stage that routes by a safety
confidence score. AgentGuard borrows the three-stage shape, the honeypot decoys, the runtime guard and the Quick/Sandbox/Deep
modes, but uses Kubernetes with NetworkPolicy isolation, deterministic command execution (no API keys), per-scan canary tokens
for *proof* of exfiltration, and a verdict that reports coverage gaps. It has no LLM triage stage.
