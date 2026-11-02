#!/usr/bin/env bash
# One command to get AgentGuard demo-ready after a reboot:
#
#     bash scripts/demo_start.sh            # fix + check everything, then start the dashboard
#     bash scripts/demo_start.sh --verify   # same, plus the full real-cluster acceptance test first (~3-5 min)
#     bash scripts/demo_start.sh --check    # fix + check only, do not start the dashboard
#     bash scripts/demo_start.sh --fresh    # start with an empty History (old runs are moved aside, not deleted)
#
# It repairs what a reboot usually breaks (Docker stopped, kind node container stopped, stale kubeconfig,
# stale AGENTGUARD_* variables, leftover sandbox pods) and tells you in plain words if something needs you.
set -uo pipefail
cd "$(dirname "$0")/.."

CLUSTER="${AGENTGUARD_KIND_CLUSTER:-agentguard}"
PORT="${PORT:-8080}"
VERIFY=0; CHECK_ONLY=0; FRESH=0
for arg in "$@"; do
  case "$arg" in
    --verify) VERIFY=1 ;;
    --check)  CHECK_ONLY=1 ;;
    --fresh)  FRESH=1 ;;
    *) echo "usage: $0 [--verify] [--check] [--fresh]"; exit 2 ;;
  esac
done

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
step()  { printf '\n== %s\n' "$*"; }
ok()    { green "   OK   $*"; }
warn()  { printf '\033[33m   WARN %s\033[0m\n' "$*"; }
fail()  { red "   FAIL $*"; echo; red "Fix the line above, then run this script again. Quick (static) scans still work without Kubernetes:"; red "   python -m agentguard.cli web --host 0.0.0.0 --port $PORT"; exit 1; }

step "1/7 Clean shell"
# Old handoff exports break things (Ollama replaced the sandbox harness; stale scanner paths hid the installs).
unset AGENTGUARD_AGENT_MODE AGENTGUARD_OLLAMA_URL AGENTGUARD_OLLAMA_CIDR AGENTGUARD_OLLAMA_MODEL \
      AGENTGUARD_CISCO_COMMAND AGENTGUARD_NVIDIA_COMMAND AGENTGUARD_ENTRYPOINT
if [ -x .venv/bin/python ]; then PY=".venv/bin/python"; else PY="$(command -v python3)"; warn "no .venv found, using $PY"; fi
ok "Python: $($PY --version 2>&1) ($PY)"
leftover="$(env | grep '^AGENTGUARD_' || true)"
[ -z "$leftover" ] && ok "no AGENTGUARD_* variables set" || warn "still set (intended?): $leftover"

step "2/7 Docker"
if ! docker info >/dev/null 2>&1; then
  warn "Docker is not answering; trying to start it (may ask for your sudo password)"
  sudo systemctl start docker
  for _ in $(seq 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
fi
docker info >/dev/null 2>&1 || fail "Docker is not running or you are not in the docker group (try: sudo systemctl start docker ; newgrp docker)"
ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)"

step "3/7 kind cluster '$CLUSTER'"
nodes="$(docker ps -a --filter "label=io.x-k8s.kind.cluster=$CLUSTER" --format '{{.Names}} {{.State}}')"
[ -n "$nodes" ] || fail "no kind cluster named '$CLUSTER' exists (see docs/KALI-QUICKSTART.md section 2.1 to create it)"
while read -r name state; do
  if [ "$state" != "running" ]; then
    warn "node container $name is $state; starting it"
    docker start "$name" >/dev/null || fail "could not start $name"
  fi
done <<< "$nodes"
kind export kubeconfig --name "$CLUSTER" >/dev/null 2>&1 || warn "kind export kubeconfig failed (continuing with the existing kubeconfig)"
kubectl config use-context "kind-$CLUSTER" >/dev/null 2>&1 || warn "could not switch kubectl context to kind-$CLUSTER"
echo "   waiting for the Kubernetes API (up to 2 min)..."
for _ in $(seq 60); do kubectl get nodes >/dev/null 2>&1 && break; sleep 2; done
kubectl get nodes >/dev/null 2>&1 || fail "kubectl cannot reach the cluster"
kubectl wait --for=condition=Ready nodes --all --timeout=180s >/dev/null 2>&1 || fail "nodes are not Ready after 3 minutes (kubectl get nodes)"
ok "nodes Ready: $(kubectl get nodes --no-headers | awk '{print $1":"$2}' | tr '\n' ' ')"

step "4/7 NetworkPolicy engine (Calico) and sink"
if kubectl -n kube-system get daemonset calico-node >/dev/null 2>&1; then
  kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s >/dev/null 2>&1 \
    && ok "calico-node running" || fail "calico-node is not ready (kubectl -n kube-system get pods)"
else
  warn "calico-node not found; AgentGuard's isolation proof will refuse to run skills if policies are not enforced"
fi
if kubectl -n agentguard-sandbox get deployment agentguard-sink >/dev/null 2>&1; then
  kubectl -n agentguard-sandbox rollout status deployment/agentguard-sink --timeout=120s >/dev/null 2>&1 \
    && ok "sink running" || warn "sink not ready yet; the first Sandbox Scan re-applies and waits for it"
else
  ok "sink not deployed yet (the first Sandbox Scan creates it)"
fi
kubectl -n agentguard-sandbox delete pod -l agentguard.io/role=skill-sandbox --ignore-not-found --wait=false >/dev/null 2>&1 \
  && ok "no leftover sandbox pods" || true

step "5/7 Sandbox images"
tag="$($PY -m agentguard.cli prepare-sandbox 2>/dev/null | tail -n 1)" || tag=""
[ -n "$tag" ] && ok "images ready (tag $tag)" || fail "prepare-sandbox failed; run: $PY -m agentguard.cli prepare-sandbox"

step "6/7 Cisco + NVIDIA scanners"
$PY -m agentguard.cli scanners || warn "a scanner is missing; run: bash scripts/install_scanners.sh  (Quick scans still work with the native rules)"

if [ "$VERIFY" = 1 ]; then
  step "Acceptance test on the real cluster (this runs five sandbox scans)"
  $PY scripts/verify_sandbox.py || fail "verify_sandbox.py reported failures (see above)"
fi

step "7/7 Dashboard"
if [ "$FRESH" = 1 ] && [ -d runs/web ]; then
  mv runs/web "runs/web-old-$(date +%Y%m%d-%H%M%S)" && ok "old History moved aside"
fi
if [ "$CHECK_ONLY" = 1 ]; then
  green "All checks done (--check: dashboard not started)."
  exit 0
fi
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  fail "port $PORT is already in use (an old dashboard still running? stop it with Ctrl+C in its terminal, or: PORT=8081 bash scripts/demo_start.sh)"
fi
green "Ready. Open  http://127.0.0.1:$PORT  in the browser (Ctrl+C here stops the dashboard)."
exec $PY -m agentguard.cli web --host 0.0.0.0 --port "$PORT"
