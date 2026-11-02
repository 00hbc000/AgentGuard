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

GitHub repository URLs can be scanned directly. Standard repository links and
branch/subdirectory links such as `/tree/main/skills/my-skill` are accepted; the repository is shallow-cloned
into a temporary workspace and its contents are never executed:

```bash
python -m agentguard.cli scan https://github.com/trailofbits/overtly-malicious-skills \
	--output artifacts/github-scan

# Scan one skill inside a collection repository
python -m agentguard.cli scan \
	https://github.com/trailofbits/overtly-malicious-skills/tree/main/skills/csv-summarizer \
	--output artifacts/github-skill
```

Exit codes: `0` is below the configured threshold, `1` meets it, and `2` means malformed input, incomplete analysis, or scanner error. Use `--fail-on-severity INFO|LOW|MEDIUM|HIGH|CRITICAL` to change the threshold.

Dynamic review is opt-in for the CLI. Gate-driven mode escalates ambiguous static evidence:

```bash
python main.py scan fixtures/combined-chain --no-external --dynamic --output runs/dynamic
```

For UI testing without executing a skill or claiming Kubernetes telemetry, use the explicitly synthetic demo:

```bash
python main.py scan fixtures/safe-minimal --no-external --demo-dynamic --output runs/demo
```

The real dynamic runner requires a kind cluster, Docker, kubectl, and a
NetworkPolicy-enforcing CNI. It builds and loads the sandbox and sink images,
proves that public internet egress is blocked while the internal sink is
reachable, then runs the configured entrypoint in the sandbox pod. If those
requirements are not met, the scan fails closed and reports that no skill code
was executed.

The website accepts public GitHub, GitLab, and Bitbucket URLs and runs native,
configured external scanners, and forced dynamic analysis synchronously for
the submitted skill. Use one skill URL at a time; a repository containing
multiple `SKILL.md` files must provide a `/tree/<ref>/skills/<name>` subpath.
Cisco and NVIDIA are shown as skipped until their commands are installed and
configured. See
[docs/VERIFICATION.md](docs/VERIFICATION.md) for the Kali evidence checklist.

For a complete Kali smoke test after rebuilding images:

```bash
./scripts/kali_demo_verify.sh \
  https://github.com/trailofbits/overtly-malicious-skills/tree/main/skills/csv-summarizer
```

The CSV sample is benign and should produce zero findings. Use the ignored
`fixtures/combined-chain` fixture to demonstrate native static findings.

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

## Team handoff

See [docs/TEAM-HANDOFF.md](docs/TEAM-HANDOFF.md) for cloning the shared branch, setting up Kali/Windows environments, running tests, configuring external scanners, and starting the findings dashboard.
