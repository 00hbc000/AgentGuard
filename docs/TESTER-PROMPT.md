# Tester prompt: static scanner compatibility run

Copy this pro mpt to the Kali test operator.

---

You are testing AgentGuard's static scanner integration. Do not modify the AgentGuard source code. Do not execute any scanned skill, script, package installer, post-install hook, agent workflow, or benchmark dynamic executor. Work only in a disposable Kali VM or isolated test host.

## Goal

Produce a complete raw-artifact package that lets the developer implement reliable adapters, normalization, and orchestration for:

- Cisco Skill Scanner
- NVIDIA SkillSpector
- AgentGuard native rules

SkillWard is reference material only. Do not install or run SkillWard.

## Inputs

Use the AgentGuard repository's `docs/TESTING-PROTOCOL.md` as the authoritative test plan. Use the MaliciousAgentSkillsBench checkout only as a metadata/reference source:

- URL: https://github.com/protectskills/MaliciousAgentSkillsBench
- Expected revision: `f7d28b1a9de4eb33d552529cf79d1065d765f6c3`
- Do not bypass redacted benchmark URLs.
- Do not add benchmark data or scanner checkouts to the AgentGuard Git repository.

Create the fixture corpus described in the protocol. Fixtures must be inert and must never contain real credentials or live attacker infrastructure. Use `example.invalid` for documentation URLs and comments such as `# static test only` to make execution prohibition explicit.

## Environment setup

Create separate environments for Cisco and NVIDIA. Record every command and version. Do not configure API keys or `.env` files.

Verify:

```bash
python --version
git --version
skill-scanner --help
skillspector --version
```

If a dependency cannot be installed, do not improvise. Record the exact error and continue with the other tests.

## Required runs

For every fixture, run Cisco with:

```bash
skill-scanner scan <fixture> --use-behavioral --format json --output artifacts/cisco/<fixture>.json
```

For every fixture, run NVIDIA with:

```bash
skillspector scan <fixture> --no-llm --format json --output artifacts/nvidia/<fixture>.json
```

Run AgentGuard with:

```bash
python main.py scan <fixture> --no-external --output artifacts/agentguard
```

For one safe fixture and the combined-chain fixture, also generate SARIF with Cisco and NVIDIA. Run the same safe and combined fixtures twice and compare finding IDs, rule IDs, locations, severities, and fingerprints for determinism.

Capture stdout, stderr, exit code, duration, exact argument array, UTC timestamps, tool version, source commit, and JSON parse status for every run. Keep raw reports unchanged.

## Required observations

For each tool and fixture, record:

- accepted input forms and whether a directory or `SKILL.md` file is required;
- whether malformed frontmatter fails, warns, or produces a partial report;
- whether a single file, nested directory, archive, symlink, hidden file, binary, and oversized file are accepted;
- static analyzers actually enabled;
- LLM/cloud/network behavior, especially OSV lookup behavior;
- output schema and every field present in a finding;
- path and line-number conventions;
- severity vocabulary and confidence type/range;
- exit code for clean, findings, malformed input, and timeout/error;
- whether stdout contains logs mixed with JSON;
- whether `--output` writes a report while still printing a summary;
- repeated-run determinism;
- timeout and partial-output behavior.

Do not infer a field from documentation if it is absent in the actual report. Record `null` or `missing` explicitly.

## Deliverables

Return an archive containing exactly this structure, with no secrets:

```text
artifacts/
  environment.json
  benchmark_revision.txt
  fixtures/<fixture>/manifest.json
  cisco/<fixture>.json
  cisco/<fixture>.stdout
  cisco/<fixture>.stderr
  cisco/<fixture>.meta.json
  nvidia/<fixture>.json
  nvidia/<fixture>.stdout
  nvidia/<fixture>.stderr
  nvidia/<fixture>.meta.json
  agentguard/<fixture>.json
  agentguard/<fixture>.meta.json
  comparison.json
  tester-notes.md
```

`comparison.json` must contain one record per fixture and tool with expected signals, observed categories, finding count, maximum severity, parse status, exit code, and notes.

`tester-notes.md` must list installation blockers, unsupported inputs, network observations, schema surprises, non-determinism, and any stop condition encountered.

## Stop immediately if

- any scanner executes a fixture or its code;
- an LLM, cloud analyzer, VirusTotal upload, or runtime sandbox activates;
- credentials are requested or printed;
- an archive escapes its extraction directory;
- a scanner hangs beyond its timeout;
- a report cannot be tied to a pinned version/commit.

The output must be evidence, not a summary. Preserve raw stdout, stderr, reports, metadata, and exact failures.
