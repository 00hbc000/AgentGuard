# AgentGuard on Kali: from clone to a working Sandbox Scan

Follow the sections in order. Every command is meant to be pasted as-is. Anything that needs your
attention says **CHECK**.

> **Status of this guide.** The Python side (rules, runner logic, in-pod harness, dashboard, jobs,
> batches) is covered by automated tests that ran in the development sandbox. The parts that need a
> real Docker + kind + Calico cluster (NetworkPolicy enforcement, `strace` inside the pod's security
> context, Tetragon) could **not** be run there. Section 6 (`verify_sandbox.py`) is how you confirm them
> on your machine. If it fails, send me the output.

## 0. Get the code onto a new test branch

The work lives on the branch `arena/969bc471-agentguard` of `00hbc000/AgentGuard` (that branch name is
fixed by the tooling that produced it). To test without touching `main` or `team-handoff`, create your
own local branch from it:

```bash
cd ~/AgentGuard                      # or: git clone https://github.com/00hbc000/AgentGuard.git ~/AgentGuard && cd ~/AgentGuard
git status --short                   # CHECK: if you have local edits (e.g. docs/TEAM-HANDOFF.md) run: git stash
git fetch origin arena/969bc471-agentguard
git switch -c test/sandbox-e2e FETCH_HEAD
git log --oneline -3
```

If you want that test branch on GitHub too: `git push -u origin test/sandbox-e2e`.

## 1. Check what you already have

```bash
docker version --format '{{.Server.Version}}'
kind version
kubectl version --client
kind get clusters                    # expect: agentguard
kubectl get nodes                    # expect: a Ready node
kubectl -n kube-system get pods -l k8s-app=calico-node     # expect: Running (NetworkPolicy enforcement)
```

If all of that works, skip to section 3. Otherwise do section 2.

## 2. Install the missing pieces (only if section 1 failed)

```bash
sudo apt update && sudo apt install -y git python3 python3-venv python3-pip docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"      # then log out and back in (or run: newgrp docker)

# kind and kubectl
curl -Lo /tmp/kind https://github.com/kubernetes-sigs/kind/releases/latest/download/kind-linux-amd64
sudo install -m 0755 /tmp/kind /usr/local/bin/kind
curl -Lo /tmp/kubectl "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -m 0755 /tmp/kubectl /usr/local/bin/kubectl
```

A cluster whose network plugin **enforces NetworkPolicy** is mandatory: kind's default plugin may not,
and AgentGuard refuses to run a skill if its isolation probe shows the pod can reach the internet.
The usual recipe is kind without its default CNI, plus Calico:

```bash
cat > /tmp/kind-agentguard.yaml <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
YAML
kind create cluster --name agentguard --config /tmp/kind-agentguard.yaml
# Calico: use the manifest URL for a current release from https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
kubectl wait --for=condition=Ready nodes --all --timeout=300s
```

(I could not test this recipe from the development sandbox. If you already built the cluster for the
earlier handoff, keep using it.)

## 3. Python environment and unit tests

```bash
cd ~/AgentGuard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt pytest
python -m agentguard.tests.make_fixtures      # inert static fixtures (git-ignored)
pytest -q                                     # expect: all pass (about 100 tests, ~15 s)
```

`pytest` needs no Kubernetes. It runs the real in-pod harness locally and drives the runner through a fake `kubectl`.

## 4. Build the sandbox images (once)

```bash
python -m agentguard.cli prepare-sandbox
```

This builds `agentguard-sandbox:<hash>` and `agentguard-sink:<hash>` and loads them into kind. The tag
is a hash of `sandbox/`, so unchanged code reuses the images and later scans start in seconds. The first
run downloads `python:3.14-slim` and installs `strace`, so it needs internet and a few minutes.
(`./scripts/build_and_load.sh` is a wrapper for the same thing.)

## 5. Optional: Cisco and NVIDIA scanners

Native rules work without them (they show as `skipped`). To add Cisco, which I verified works:

```bash
python3 -m venv ~/.venvs/cisco && ~/.venvs/cisco/bin/pip install cisco-ai-skill-scanner
export AGENTGUARD_CISCO_COMMAND="$HOME/.venvs/cisco/bin/skill-scanner scan"
```

NVIDIA SkillSpector needs Python 3.12+ (`uv python install 3.12`), so it is a separate install; I could not
verify that adapter. Set `AGENTGUARD_NVIDIA_COMMAND` the same way only if it installs cleanly. Export the variables
in the same terminal that starts the dashboard.

## 6. Prove the sandbox works (acceptance check)

```bash
python scripts/verify_sandbox.py
```

It runs five controlled, synthetic samples through a real Sandbox Scan and checks what must be seen:

| Sample | Must produce |
|---|---|
| `benign-csv-stats` | ran its command, no findings, verdict `no_findings` |
| `runtime-exfil-sink` | CRITICAL `DYN_HONEYPOT_EXFIL` |
| `runtime-exfil-evasive` | CRITICAL `DYN_HONEYPOT_EXFIL`; static rules alone find nothing |
| `runtime-exfil-external` | HIGH `DYN_EXFIL_ATTEMPT`, no proven exfiltration |
| `runtime-env-dump` | HIGH `DYN_ENV_EXPOSED` |

Then it checks that no sandbox pod is left behind. Expected last line: `ALL CHECKS PASSED`.

**If it fails**, the message usually tells you why:

| Message | Meaning / fix |
|---|---|
| `kubectl cannot reach a Kubernetes cluster` | cluster is not running: `kind get clusters`, `kubectl config use-context kind-agentguard` |
| `NetworkPolicy isolation proof failed: sandbox reached the public internet` | the CNI does not enforce policies. Install Calico (section 2). AgentGuard refuses to run the skill. |
| `sandbox could not reach the sink` | the sink pod is not ready: `kubectl -n agentguard-sandbox get pods` |
| runtime events show `trace_available: false` | `strace` is not permitted by the pod's security context; scans still work through the Python guard and the sink, with less syscall evidence (only affects non-Python code) |
| image build errors | check internet/DNS for Docker, then rerun `prepare-sandbox` |

Leftover pods from an interrupted run: `kubectl -n agentguard-sandbox delete pod --all`.

## 7. Run the dashboard

```bash
python -m agentguard.cli web --host 0.0.0.0 --port 8080
```

Open `http://127.0.0.1:8080` in Kali (or `http://<kali-ip>:8080` from another machine; `ip -br addr` shows the IP).
The top of the page shows a readiness strip: docker / kind / kubectl / cluster / sandbox image / Cisco / NVIDIA.
Data is stored in `runs/web/` (override with `--data-dir`), so history survives restarts.

### Test plan (do these in order)

1. **Control, Quick:** sample library -> `benign-csv-stats` -> Quick Scan. Verdict `NO FINDINGS`.
2. **Control, Sandbox:** same sample -> Sandbox Scan. You should see the stage timeline (ingestion, static, gate,
   sandbox...), then verdict `NO FINDINGS` with *Runtime evidence* showing 1 command run.
3. **Static miss, runtime catch:** `runtime-exfil-evasive` -> Quick Scan says `NO FINDINGS`.
   Run it again as Sandbox Scan: verdict **MALICIOUS - exfiltration proven at runtime**, CRITICAL `DYN_HONEYPOT_EXFIL`,
   and the *Sink events* group lists the canary names the sink received.
4. **Other runtime samples:** `runtime-exfil-sink`, `runtime-exfil-external`, `runtime-env-dump` (expectations in the table above).
5. **Public malicious skills (Quick is enough, they are static-detectable):** sample library -> Trail of Bits,
   `agent-guard-corpus` and Cisco entries. Or paste any `/tree/main/<path>` GitHub URL.
6. **Public benign controls:** the *Benign public controls* group (`anthropics/skills` and Cisco `simple-math`).
   `claude-api` shows two LOW notes: it *documents* `curl | sh` and prompt injection as things to refuse.
7. **Batch:** Batch tab -> *Add all malicious samples* and *Add all benign controls* -> Quick -> Run. The table shows
   `detected / missed / false positive` per known sample. Expected in Quick mode: every public malicious sample is
   *detected* except the three whose attack is only in prose; `runtime-exfil-evasive` is *missed* (that is what
   Sandbox mode is for).
8. **Cancel:** start a Sandbox Scan and press Cancel. The pod is deleted (`kubectl -n agentguard-sandbox get pods`).
9. **History:** History tab shows every run; download the JSON or the standalone HTML report.
10. **Restart survival:** stop the dashboard (Ctrl+C), start it again; History is still there.

Expanding a whole repository: put `https://github.com/trailofbits/overtly-malicious-skills` (no `/tree/...`) into Batch;
each skill inside becomes its own scan.

## 8. Same thing from the command line

```bash
python -m agentguard.cli scan samples/runtime-exfil-evasive --no-external --mode sandbox --output runs/evasive
python -m agentguard.cli scan https://github.com/trailofbits/overtly-malicious-skills/tree/main/skills/csv-summarizer \
    --no-external --mode quick --output runs/csv
python -m agentguard.cli list-skills https://github.com/anthropics/skills    # JSON list of skill URLs
```

Exit code `1` means findings at or above `--fail-on-severity` (default MEDIUM) and is normal for malicious skills; `2` means the
scan itself had a problem (for example the sandbox was unavailable).

## 9. Safety rules this setup keeps

- Skill code runs only in the pod: read-only root, non-root user, all capabilities dropped, no service-account token,
  egress limited to the sink and cluster DNS.
- Remote skills are downloaded by `git` (hooks off, no submodules, symlinks removed) and read as text by the host.
- The dashboard accepts only public GitHub/GitLab/Bitbucket URLs and library samples, never local paths.
- `runs/`, `fixtures/` and reports are git-ignored; do not commit them. Do not put real credentials anywhere near this.
