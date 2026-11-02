#!/usr/bin/env bash
set -u

check() {
  local name="$1"
  shift
  if "$@" >/tmp/agentguard-verify.out 2>&1; then
    printf 'PASS\t%s\n' "$name"
  else
    printf 'FAIL\t%s\t%s\n' "$name" "$(tr '\n' ' ' </tmp/agentguard-verify.out)"
  fi
}

check "python tests" python -m pytest -q -m "not integration"
check "kind context" kubectl config current-context
check "cluster node" kubectl get nodes
check "calico" kubectl -n kube-system get pods -l k8s-app=calico-node
check "tetragon" kubectl -n kube-system get daemonset tetragon
check "sandbox policies" kubectl -n agentguard-sandbox get networkpolicy
check "ollama" curl -fsS http://127.0.0.1:11434/api/tags
check "no leftover sandbox pods" kubectl -n agentguard-sandbox get pods
