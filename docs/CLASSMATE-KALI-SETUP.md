# AgentGuard on Kali Linux

Use this guide to get the complete AgentGuard project and test a real GitHub skill repository.

## 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip
```

## 2. Clone the complete project

```bash
cd ~
rm -rf AgentGuard

git clone --branch team-handoff \
  https://github.com/00hbc000/AgentGuard.git \
  AgentGuard

cd ~/AgentGuard
```

Check the branch:

```bash
git branch --show-current
git log --oneline -1
```

Expected branch:

```text
team-handoff
```

## 3. Install Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run the tests:

```bash
pytest -q
```

## 4. Start the web interface

```bash
python -m agentguard.cli web --host 0.0.0.0 --port 8080
```

Keep this terminal open. Find the Kali IP in a second terminal:

```bash
ip -br addr
```

Open the dashboard in Kali at:

```text
http://127.0.0.1:8080
```

From another computer, use:

```text
http://KALI_IP:8080
```

## 5. Test a real GitHub skill directly

Paste this URL into the AgentGuard dashboard input:

```text
https://github.com/trailofbits/overtly-malicious-skills/tree/main/skills/csv-summarizer
```

Click `Run static scan`.

AgentGuard will:

1. Shallow-clone the GitHub repository.
2. Select the `skills/csv-summarizer` directory.
3. Materialize it in a temporary workspace.
4. Run static analysis.
5. Display normalized findings in the dashboard.

The skill is not executed.

## 6. Test the built-in finding-rich fixture

In another terminal, from `~/AgentGuard`:

```bash
source .venv/bin/activate
python -m agentguard.tests.make_fixtures
python -m agentguard.cli scan \
  fixtures/combined-chain \
  --no-external \
  --output artifacts/showcase
```

Use this path in the dashboard:

```text
/root/AgentGuard/fixtures/combined-chain
```

This controlled fixture demonstrates credential access, external transmission, and obfuscation without executing anything.

## 7. Optional Cisco and NVIDIA scanners

Install each scanner in a separate virtual environment. Do not put their source code inside AgentGuard.

After installation, configure the commands in the same terminal used to start the dashboard:

```bash
export AGENTGUARD_CISCO_COMMAND="$HOME/.venvs/cisco-skill-scanner/bin/skill-scanner scan"
export AGENTGUARD_NVIDIA_COMMAND="$HOME/.venvs/skillspector/bin/skillspector scan"
```

Restart the dashboard after setting these variables:

```bash
CTRL+C
python -m agentguard.cli web --host 0.0.0.0 --port 8080
```

Run the GitHub scan again. The dashboard should show:

```text
cisco
nvidia
agentguard
```

Keep these disabled during static testing:

- LLM providers
- API keys
- Cisco AI Defense
- VirusTotal uploads
- NVIDIA LLM mode
- Runtime/sandbox execution

## 8. Command-line GitHub test

The same real GitHub URL can be tested without the browser:

```bash
python -m agentguard.cli scan \
  "https://github.com/trailofbits/overtly-malicious-skills/tree/main/skills/csv-summarizer" \
  --no-external \
  --output artifacts/github-skill
```

Inspect the result:

```bash
jq '.' artifacts/github-skill/csv-summarizer.json
```

## Important

Do not paste API keys into the repository or commit these directories:

```text
tools/
fixtures/
artifacts/
reports/
.venv/
.env
```

The repository already ignores them. The benchmark repositories should be treated as research inputs and should not be executed directly.
