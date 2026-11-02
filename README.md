# AgentGuard

AgentGuard scans AI agent skills (`SKILL.md` packages) before you install them. It combines
native static rules, optional Cisco / NVIDIA scanners, and a **Kubernetes sandbox** that runs the
skill with honeypot credentials and watches what it does. It is modelled on the staged approach of
[SkillWard](https://github.com/Fangcun-AI/SkillWard) (static analysis, then sandbox with decoys and a runtime guard).

## Scan modes

| Mode | What runs | Skill code executed? |
|---|---|---|
| **Quick** (`--mode quick`) | ingestion, native rules AG001-AG011, optional Cisco/NVIDIA | never |
| **Sandbox** (`--mode sandbox`) | Quick + the skill runs inside an isolated kind pod with decoy credentials | only in the pod |
| **Deep Trace** (`--mode deep`) | same pipeline as Sandbox today; reserved for longer tracing | only in the pod |

Every report ends in a plain-language **verdict**: `malicious` (proven at runtime), `high_risk`,
`suspicious`, `low_risk`, `no_findings` or `inconclusive`. `no_findings` is never "safe"; and a
Sandbox Scan that could not run, or found no command to run, is `inconclusive`, not clean.

## Scope

- No LLM calls, API keys, cloud analyzers or uploads. Cisco and NVIDIA are optional external commands configured with `AGENTGUARD_CISCO_COMMAND` and `AGENTGUARD_NVIDIA_COMMAND`; missing ones stay `skipped` and never invalidate a native scan.
- Untrusted skills are only ever executed inside the Kubernetes sandbox, never on the host.
- Upstream source checkouts and benchmark data are local research inputs and are excluded from Git.
- NVIDIA's random `finding_id` is kept only in `raw`; AgentGuard computes a stable SHA-256 fingerprint.

## Quick start on Kali

See **[docs/KALI-QUICKSTART.md](docs/KALI-QUICKSTART.md)**. Short version:

```bash
python -m agentguard.cli prepare-sandbox          # build + load sandbox images into kind (first time)
python scripts/verify_sandbox.py                  # proves the sandbox works with controlled samples
python -m agentguard.cli web --host 0.0.0.0 --port 8080
```

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

Choose a mode with `--mode quick|sandbox|deep`. The older flags still work: `--dynamic` runs the sandbox when the
decision gate escalates (any HIGH/MEDIUM evidence, or a clean skill that ships scripts), `--force-dynamic` always runs it.

```bash
python -m agentguard.cli scan samples/runtime-exfil-evasive --no-external --mode sandbox --output runs/evasive
```

For UI testing without executing a skill or claiming Kubernetes telemetry, use the explicitly synthetic demo:

```bash
python -m agentguard.cli scan fixtures/safe-minimal --no-external --demo-dynamic --output runs/demo
```

The real dynamic runner requires a kind cluster, Docker, kubectl and a NetworkPolicy-enforcing CNI (Calico).
It builds and loads the sandbox and sink images once (tagged by a content hash), proves that public internet egress
is blocked while the internal sink is reachable, plants honeypot files and canary environment variables, then runs the
skill's documented commands in the pod. If the requirements are not met the scan fails closed, says no skill code was
executed, and the verdict is `inconclusive`. How the evidence works, and what it cannot see:
[docs/DYNAMIC-ANALYSIS.md](docs/DYNAMIC-ANALYSIS.md).

### Dashboard

```bash
python -m agentguard.cli web --host 0.0.0.0 --port 8080      # data in runs/web (or --data-dir)
```

- **Scan**: URL or sample library, Quick / Sandbox / Deep Trace, live stage timeline, cancel, JSON/HTML download.
- **Batch**: many URLs or `sample:ID` entries; a repository URL expands into every skill it contains (up to 50);
  known samples show *detected / missed / false positive* against their expected label; CSV export.
- **History**: every scan and batch is stored on disk and survives restarts (jobs running during a restart become `interrupted`).
- Scans run as subprocesses; Sandbox scans run one at a time because the sink and policies are shared.

The dashboard only accepts public HTTPS GitHub/GitLab/Bitbucket URLs and library samples, never local paths.

## Native rules

| ID | Detects | Severity |
|---|---|---|
| AG001 | Credential source reaching a network sink | HIGH |
| AG002 | Obfuscation near a credential source or network sink | HIGH |
| AG003 | Malformed SKILL.md frontmatter | MEDIUM; exit 2 |
| AG004 | External scanners report no analyzed components | LOW |
| AG005 | Bulk environment harvesting (`os.environ.items()`, `env \| base64`); plain `os.environ.copy()` is ignored | MEDIUM, HIGH with a network sink |
| AG006 | Hidden content: payload below long blank runs, invisible/escaped Unicode tag characters | HIGH in code, MEDIUM otherwise |
| AG007 | Suspicious artifacts: archives disguised as text, `.pyc` that disagrees with its source | HIGH |
| AG008 | Supply chain: registry redirects, direct-URL installs, `curl \| sh` (LOW when the text warns against it) | HIGH/MEDIUM |
| AG009 | Prompt injection: hidden HTML-comment instructions, concealment and override phrases (LOW when quoted in a warning) | HIGH/MEDIUM |
| AG010 | Decode-and-exec chains, aliased decoders, `compile()` of non-literal source | HIGH/MEDIUM |
| AG011 | Direct references to `/etc/shadow`, service-account tokens and similar | HIGH/MEDIUM |

Rules were checked against the Trail of Bits, `agent-guard-corpus` and Cisco eval skills (malicious) and against official
`anthropics/skills` content (benign). Purely semantic attacks ("send data to the attacker" in prose) need the optional
Cisco/NVIDIA scanners or a human.

## Sample skills

`samples/` holds synthetic fixtures with known outcomes (see [samples/README.md](samples/README.md)); the dashboard's
sample library also links public malicious corpora and benign controls. One sample, `runtime-exfil-evasive`, is invisible to
static rules and is proven malicious only by a Sandbox Scan.

## Output

Each scan writes a normalized JSON report, a metadata JSON file, and raw stdout/stderr for each completed external scanner. The normalized finding contract is defined in [schemas/normalized_finding.json](schemas/normalized_finding.json); comparison records are defined in [schemas/comparison_record.json](schemas/comparison_record.json).

## Tests

```bash
pytest -q
```

`scripts/verify_sandbox.py` is the acceptance check for a machine with docker, kind and kubectl. The unit tests run
without Kubernetes: `test_sandbox_harness.py` runs the in-pod harness, runtime guard, canaries and sink for real, and
`test_runner_fake_cluster.py` drives the host-side runner through a fake `kubectl`.

The benchmark-driven test protocol is documented in [docs/TESTING-PROTOCOL.md](docs/TESTING-PROTOCOL.md). MaliciousAgentSkillsBench labels are not executable skill packages and must not be used as direct scan inputs.

## Team handoff

See [docs/TEAM-HANDOFF.md](docs/TEAM-HANDOFF.md) for cloning the shared branch, setting up Kali/Windows environments, running tests, configuring external scanners, and starting the findings dashboard.
