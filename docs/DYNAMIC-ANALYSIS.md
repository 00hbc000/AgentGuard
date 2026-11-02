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

## Known limits

- The runtime guard covers **Python** only; non-Python code is seen through `strace` (when allowed) and the sink.
- Cluster DNS is allowed, so DNS-based exfiltration is possible; the sink would not see it.
- Skills that behave differently when they detect a sandbox, wait out the time limit, or need real credentials/APIs to
  reach their payload can pass. Absence of findings is not a safety guarantee.
- Prose-only attacks (prompt injection) are static-stage findings; the sandbox does not run an LLM unless
  `AGENTGUARD_AGENT_MODE=ollama` is configured (existing optional path, not part of the default flow).
- Tetragon (eBPF) evidence is used when the DaemonSet is present and events correlate to the pod; otherwise tier `fallback`.
- Verified in development without Kubernetes: the harness, guard, canaries, sink, collector, runner orchestration (via a fake
  `kubectl`). Verified only on a real cluster by `scripts/verify_sandbox.py`: NetworkPolicy enforcement, `strace` under the pod's
  security context, Tetragon.

## Differences from SkillWard

SkillWard (Apache-2.0) runs an LLM agent inside a Docker container and adds an LLM triage stage that routes by a safety
confidence score. AgentGuard borrows the three-stage shape, the honeypot decoys, the runtime guard and the Quick/Sandbox/Deep
modes, but uses Kubernetes with NetworkPolicy isolation, deterministic command execution (no API keys), per-scan canary tokens
for *proof* of exfiltration, and a verdict that reports coverage gaps. It has no LLM triage stage.
