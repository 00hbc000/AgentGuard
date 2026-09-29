# AgentGuard

AgentGuard is a static-only orchestrator for Cisco Skill Scanner, NVIDIA SkillSpector, and native gap rules. It normalizes findings without executing scanned skill content.

## Scope

- No LLM calls, API keys, cloud analyzers, uploads, or runtime sandbox execution.
- Cisco and NVIDIA are optional external commands configured with `AGENTGUARD_CISCO_COMMAND` and `AGENTGUARD_NVIDIA_COMMAND`.
- Upstream source checkouts and benchmark data are local research inputs and are excluded from Git.
- NVIDIA's random `finding_id` is kept only in `raw`; AgentGuard computes a stable SHA-256 fingerprint.

## Install

```bash
python -m venv .venv
.venv\\Scripts\\activate       # Windows
source .venv/bin/activate       # Kali/Linux
python -m pip install -r requirements.txt
```

## Generate fixtures

Fixtures are intentionally ignored by Git and contain inert static examples only:

```bash
python -m agentguard.tests.make_fixtures
```

## Scan

Native rules only:

```bash
python -m agentguard.cli scan fixtures/combined-chain --no-external --output artifacts/agentguard
```

Both configured upstream scanners plus native rules:

```bash
export AGENTGUARD_CISCO_COMMAND='skill-scanner scan'
export AGENTGUARD_NVIDIA_COMMAND='skillspector scan'
python -m agentguard.cli scan fixtures/combined-chain --output artifacts/agentguard
```

Batch and comparison:

```bash
python -m agentguard.cli scan-all fixtures --no-external --output artifacts/agentguard
python -m agentguard.cli compare --input artifacts/agentguard --output artifacts/comparison.json
```

Exit codes: `0` is below the configured threshold, `1` meets it, and `2` means malformed input, incomplete analysis, or scanner error. Use `--fail-on-severity INFO|LOW|MEDIUM|HIGH|CRITICAL` to change the threshold.

## Native gap rules

| ID | Gap | Severity |
|---|---|---|
| AG001 | Credential source reaching a network sink | HIGH |
| AG002 | Obfuscation near a credential source or network sink | HIGH |
| AG003 | Malformed SKILL.md frontmatter | MEDIUM; exit 2 |
| AG004 | External scanners report no analyzed components | LOW |

## Output

Each scan writes a normalized JSON report, a metadata JSON file, and raw stdout/stderr for each completed external scanner. The normalized finding contract is defined in [schemas/normalized_finding.json](schemas/normalized_finding.json); comparison records are defined in [schemas/comparison_record.json](schemas/comparison_record.json).

## Tests

```bash
pytest -q
```

The benchmark-driven test protocol is documented in [docs/TESTING-PROTOCOL.md](docs/TESTING-PROTOCOL.md). MaliciousAgentSkillsBench labels are not executable skill packages and must not be used as direct scan inputs.
