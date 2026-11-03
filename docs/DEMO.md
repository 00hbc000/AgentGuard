# Demo day: start-up and a 6-minute walkthrough

## Before the professor arrives (10 minutes, do this first)

```bash
cd ~/AgentGuard
git fetch origin arena/969bc471-agentguard && git switch test/sandbox-e2e && git merge --ff-only FETCH_HEAD   # needs internet; skip if you already pulled
source .venv/bin/activate
bash scripts/demo_start.sh --verify
```

`demo_start.sh` repairs what a reboot breaks (starts Docker and the kind node if stopped, re-selects the cluster, waits for
Calico and the sink, removes stray pods, checks images and the Cisco/NVIDIA scanners), then `--verify` runs the five real-cluster
checks (3-5 minutes). It ends with `ALL CHECKS PASSED` and starts the dashboard at **http://127.0.0.1:8080**.
Leave that terminal open (Ctrl+C stops the dashboard). After this, run `bash scripts/demo_start.sh --fresh` only if you want an empty History.

If a line says FAIL it tells you what to do. If you cannot fix it in a few minutes, Quick (static) scans work without Kubernetes, so
you can still demonstrate Part 1.

## What to say and click (about 6 minutes)

**Idea in one sentence:** static analysis finds *suspicion*; the sandbox produces *proof*.

1. **Show the top strip**: docker, kind, kubectl, cluster, sandbox image, Cisco scanner, NVIDIA scanner, monitoring: tetragon. (30 s)
2. **Stage 1, static, three engines.** Sample library -> `runtime-env-dump` -> *Quick Scan* (~20 s). Verdict `HIGH RISK`.
   Point at the timeline (Cisco, NVIDIA, native rules) and that findings are tagged by engine. (1 min)
3. **A benign skill.** `benign-csv-stats` -> *Sandbox Scan*. Verdict `NO FINDINGS`, runtime evidence "1 command run". Say: "no findings is never labelled safe". (1 min)
4. **The key demo.** `runtime-exfil-evasive` -> *Sandbox Scan*. Static engines only raise suspicion; at runtime the skill reads planted
   fake credentials and sends them out. Verdict **MALICIOUS - exfiltration proven at runtime**; open *Sink events*: the canary names
   the sink actually received. Say: "a unique secret planted for this scan appeared in the sink's request log, so it is proof, not a guess". (2 min)
5. **Isolation.** Open the report's runtime section: the sandbox proved the pod cannot reach the internet before running the skill.
   `runtime-exfil-external` -> Sandbox: HIGH `DYN_EXFIL_ATTEMPT` (attempt blocked, therefore not "proven"). (1 min)
6. **History and download**: History tab, open a report, download the JSON/HTML. (30 s)

Do **not** live-run the full Batch of 25 (about 7 minutes) or large benign skills such as `claude-api` (NVIDIA needs ~4.5 min).
If asked about accuracy, the measured Quick-mode result is 20 of 20 malicious samples flagged, 3 clean, and 2 large benign Anthropic skills flagged
`HIGH RISK` by the external engines; that is exactly why the sandbox stage exists.

## Likely questions

- *Why not just run the skill?* Hostile code: it runs only in a read-only, non-root, no-capabilities pod whose egress goes only to our sink.
- *How do you know it is exfiltration?* Canary tokens unique per scan, seen in the sink's log (and in base64/hex/url forms).
- *Limits?* Python-only runtime guard (strace covers the rest), DNS is allowed, prose-only attacks need LLM review, a skill that detects the sandbox can pass.
- *Did you only test your own samples?* The five controlled samples are ours. We also picked 12 public MalSkillBench skills (real reverse shells, credential theft, downloaders) by reading their code; `python scripts/eval_public_dynamic.py` runs them in the sandbox and reports what each engine saw. Quote only the results you have actually run; do not run the full script live (10-20 minutes).
- *What is Deep mode?* Sandbox plus an optional Ollama agent; off by default and never replaces the scripted run.

## If something goes wrong on the day

| Symptom | Do |
|---|---|
| dashboard page does not open | `bash scripts/demo_start.sh` again; check `http://127.0.0.1:8080` in the same VM |
| Sandbox Scan says inconclusive / "sandbox unavailable" | `bash scripts/demo_start.sh --check` and read the FAIL line |
| stray pods | `kubectl -n agentguard-sandbox delete pod --all` |
| Cisco/NVIDIA chip missing | `env \| grep AGENTGUARD` (should be empty), then `bash scripts/install_scanners.sh` |
| port 8080 busy | `PORT=8081 bash scripts/demo_start.sh` |
