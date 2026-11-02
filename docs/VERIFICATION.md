# AgentGuard verification

## Two-machine workflow

Develop and run unit tests on Windows. Run Kubernetes integration checks on
Kali; the Windows host must never execute scanned skill code.

```bash
cd ~/AgentGuard
git pull
source .venv/bin/activate
pytest -q -m "not integration"
bash scripts/kali_verify.sh
```

The dynamic runner builds uniquely tagged images, loads them into the
`agentguard` kind cluster, proves the sandbox network boundary, executes one
selected skill, collects events, and deletes the pod in `finally`.

## Evidence checklist

For each scan, inspect the JSON report and confirm:

- `source`, `materialized_path`, and `ingestion.commit_sha` identify one skill;
- `stages` identifies native, Cisco, NVIDIA, gate, and dynamic status;
- skipped or failed scanners are explicit and make the result `partial`;
- dynamic events include the scan token and sandbox image identity;
- isolation events show public network and external DNS failure plus sink success;
- `dynamic.monitoring_tier` is `tetragon` only with a correlated event for the
  current pod; otherwise it is `fallback`;
- `DYN_HONEYPOT_EXFIL` is present only for a current-scan marker and forces
  `CRITICAL`;
- `kubectl -n agentguard-sandbox get pods,secrets,configmaps` has no leftovers.

## External scanners

Configure local binaries without putting credentials in the repository:

```bash
export AGENTGUARD_CISCO_COMMAND="$HOME/.venvs/cisco-skill-scanner/bin/skill-scanner scan"
export AGENTGUARD_NVIDIA_COMMAND="$HOME/.venvs/skillspector/bin/skillspector scan"
```

The report records each scanner as `completed`, `skipped`, or `failed`.

## Known verification boundary

Unit tests run on Windows. Actual Docker, kind, Calico, Ollama, Tetragon,
NetworkPolicy enforcement, image identity, and cleanup remain **NOT VERIFIED**
until the commands above are run on Kali and their output is retained.
