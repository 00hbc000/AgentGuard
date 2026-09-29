# AgentGuard scanner research

Status: initial static-analysis study

## Pinned upstream sources

The upstream repositories are external references and are intentionally not
vendored into the public AgentGuard repository. Local checkouts may exist for
private study, but they are ignored by Git. AgentGuard records the upstream
URLs and commit pins instead.

| Tool | Local source | Commit | Static entry point |
|---|---|---|---|
| Cisco Skill Scanner | [GitHub](https://github.com/cisco-ai-defense/skill-scanner) | `877a41320066cdee172095356c6818208ba7a806` | `skill-scanner scan <skill>` or `SkillScanner.scan_skill()` |
| NVIDIA SkillSpector | [GitHub](https://github.com/NVIDIA/skillspector) | `88312190c7c69febed817a8b1e18462793dea33b` | `skillspector scan <target> --no-llm` or `skillspector.graph.invoke()` |
| SkillWard | [GitHub](https://github.com/Fangcun-AI/SkillWard) | `7e406b78dcc18a1cb95cd6a616c3b9f5928d4345` | Reference only; not executed by AgentGuard |

These are moving default-branch snapshots. AgentGuard should record the commit used for every scan and should not silently update them during a run.

## What each tool actually does

### Cisco Skill Scanner

- Core deterministic pipeline: static signatures/YARA, bytecode, shell-pipeline, correlation, and policy processing.
- Optional static dataflow: `--use-behavioral`; this uses AST parsing and forward taint analysis and does not execute skill code.
- Optional network-dependent analyzers exist, including OSV, VirusTotal, and Cisco AI Defense. They must be explicit in AgentGuard because they can transmit metadata or files.
- LLM and meta-analysis are optional and require provider configuration. They are excluded from the first AgentGuard static profile.
- Useful control flags for later profiles: `--policy`, `--custom-rules`, `--taxonomy`, `--threat-mapping`, `--cel-mode`, `--lenient`, `--skill-file`, and `--format json|sarif`.
- JSON findings contain stable normalization inputs such as `id`, `rule_id`, `category`, `severity`, `title`, `description`, `file_path`, `line_number`, `snippet`, `remediation`, `analyzer`, and `metadata`.
- Static-only baseline command:

```text
skill-scanner scan <skill-dir> --use-behavioral --format json --output <report.json>
```

### NVIDIA SkillSpector

- `resolve_input` accepts a local directory, single file, zip, Git URL, or file URL and materializes a local scan directory.
- `build_context` creates the component inventory, file cache, manifest, AST cache, and inspection ledger.
- Static analyzer nodes run in parallel. The static surface includes pattern analyzers, YARA, AST behavior, taint tracking, OSV dependency lookup, and MCP least-privilege/tool-poisoning checks.
- `--no-llm` disables semantic evaluation and keeps the skill contents local. OSV dependency coordinates may still be sent to `api.osv.dev` unless that behavior is disabled or unavailable.
- JSON output includes `skill`, `risk_assessment`, `components`, `issues`, and `metadata`; SARIF 2.1.0 is also available.
- Static-only baseline command:

```text
skillspector scan <skill-dir> --no-llm --format json --output <report.json>
```

- Programmatic graph invocation is available, but the first adapter should prefer the CLI/report contract until dependency isolation and cleanup behavior are tested.

### SkillWard reference

- SkillWard is the architectural and product reference for AgentGuard, not an
  execution dependency or a scanner adapter.
- Its useful design ideas are staged analysis, evidence-rich findings, explicit
  static/semantic/runtime boundaries, confidence-based routing, and a future
  isolated sandbox stage.
- Its `--stage pre-scan` combines static analysis with LLM scoring, so it is not
  a pure static reference implementation for this milestone.
- Its comparison and case-study documents help identify coverage gaps between
  scanners and guide AgentGuard's custom rules.
- AgentGuard must not import SkillWard's embedded scanner or treat SkillWard
  findings as a third scan result.

## Integration decision

The first AgentGuard implementation should use two upstream scanner adapters
plus one native custom-rule engine, with one shared input directory and one
output directory per run:

1. Materialize or validate a skill package without executing any skill file.
2. Run Cisco static plus behavioral analysis.
3. Run NVIDIA with `--no-llm` and JSON output.
4. Run AgentGuard custom static rules to cover gaps identified from Cisco,
   NVIDIA, and SkillWard's documented comparison cases.
5. Capture command, commit, environment, duration, exit code, stdout/stderr,
   and raw report for each scanner/rule engine.
6. Normalize findings only after raw reports are persisted.

Subprocess isolation is preferred for Cisco and NVIDIA initially. It prevents
dependency conflicts and preserves each tool's own loader, policy, and output
behavior. AgentGuard custom rules should run in its own small, dependency-light
package and must never execute code from the scanned skill.

## Draft universal finding contract

The normalizer should preserve raw data and map each finding to these fields:

```json
{
  "scan_id": "uuid",
  "tool": "cisco|nvidia|agentguard",
  "tool_version": "string|null",
  "source_commit": "git sha",
  "finding_id": "tool-native id",
  "rule_id": "tool-native rule id",
  "category": "normalized category",
  "severity": "info|low|medium|high|critical",
  "confidence": "number|null",
  "message": "short finding title/message",
  "description": "full tool explanation",
  "remediation": "string|null",
  "location": {
    "path": "relative path|null",
    "start_line": "integer|null",
    "end_line": "integer|null",
    "snippet": "string|null"
  },
  "evidence": {},
  "raw_finding": {}
}
```

The normalizer must never discard unknown fields. Severity and category mappings need an explicit versioned table, not string guesses embedded in adapters.

## Important boundaries and risks

- A clean result is not a security certification for any of the three tools.
- LLM-backed scans are disabled until a provider is deliberately configured. Local Ollama or an authenticated local CLI may be evaluated later without adding a hosted API key.
- Cisco and NVIDIA can perform outbound dependency lookups even in otherwise static profiles; the orchestrator must expose this in scan metadata and support an offline policy.
- Tool reports use different concepts: Cisco uses `Finding` and `ScanResult`, NVIDIA uses `Finding` plus risk assessment/SARIF, and SkillWard reuses Cisco-like models. Deduplication must therefore use provenance plus evidence rather than rule ID alone.
- The scanners inspect untrusted skill content. AgentGuard must never import or execute code from the scanned skill, and future runtime testing must happen in a separate sandbox on Kali/Docker.
- Before deployment to Kali, reproduce the same pinned commits, Python versions, dependency lockfiles, and scanner self-tests in a clean environment.

## Next verification step

Use the reproducible matrix in `docs/TESTING-PROTOCOL.md` and the handoff in
`docs/TESTER-PROMPT.md`. Run Cisco and NVIDIA as the two upstream scanners and
AgentGuard's native rules as the third result source. Start with inert local
fixtures, capture raw JSON/SARIF and process metadata, and only then finalize
the adapters, normalization mappings, and orchestrator behavior.
