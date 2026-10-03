# AgentGuard Team Handoff

This branch contains the complete tracked AgentGuard project.

## Clone

```bash
git clone --branch team-handoff https://github.com/00hbc000/AgentGuard.git
cd AgentGuard
```

The branch contains only AgentGuard source, tests, schemas, and documentation. It intentionally does not contain upstream scanner checkouts, benchmark datasets, generated fixtures, scan reports, API keys, `.env` files, or virtual environments.

## Install

Linux/Kali:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Verify

```bash
pytest -q
```

Expected result: all tests pass.

## Generate safe fixtures

```bash
python -m agentguard.tests.make_fixtures
```

Fixtures are local and ignored by Git.

## Run a native static scan

```bash
python -m agentguard.cli scan fixtures/combined-chain --no-external --output artifacts/showcase
```

## Run Cisco and NVIDIA adapters

Install each upstream scanner separately in its own virtual environment. Then configure the executable commands without committing credentials:

```bash
export AGENTGUARD_CISCO_COMMAND="$HOME/.venvs/cisco-skill-scanner/bin/skill-scanner scan"
export AGENTGUARD_NVIDIA_COMMAND="$HOME/.venvs/skillspector/bin/skillspector scan"
python -m agentguard.cli scan fixtures/combined-chain --output artifacts/full-static
```

The orchestrator always invokes NVIDIA with `--no-llm` and Cisco with static behavioral analysis. Keep cloud analyzers, LLM providers, uploads, and runtime execution disabled for static testing.

## Run the findings dashboard

```bash
python -m agentguard.cli web --host 0.0.0.0 --port 8080
```

Open `http://127.0.0.1:8080` locally, or use the Kali VM address from another machine.

## Collaboration workflow

Create work branches from `team-handoff`:

```bash
git switch -c feature/your-topic
git push -u origin feature/your-topic
```

Keep generated content out of commits. Before opening a pull request:

```bash
pytest -q
git status
```

Do not commit:

- `tools/`
- `fixtures/`
- `artifacts/`
- `reports/`
- `.venv/`
- `.env`
- API keys or scanner credentials
