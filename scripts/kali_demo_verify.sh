#!/usr/bin/env bash
set -euo pipefail

source="${1:?Usage: $0 <public-skill-url>}"
output="${2:-runs/kali-demo-$(date +%Y%m%d-%H%M%S)}"

echo "== AgentGuard environment =="
kubectl config current-context
kubectl get nodes
kubectl -n kube-system get daemonset tetragon
kubectl -n kube-system get pods -l k8s-app=calico-node
kubectl -n agentguard-sandbox get networkpolicy

echo "== External scanner availability =="
command -v skill-scanner || true
command -v skillspector || true

echo "== Static + forced dynamic scan =="
python -m agentguard.cli scan "$source" \
  --force-dynamic \
  --output "$output"

report="$(find "$output" -maxdepth 1 -name '*.json' ! -name '*.meta.json' -print | sort | head -n 1)"
test -n "$report"
python - "$report" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
dynamic = report.get("dynamic") or {}
print(json.dumps({
    "scan_status": report.get("scan_status"),
    "aggregate_severity": report.get("aggregate_severity"),
    "finding_count": report.get("finding_count"),
    "stages": report.get("stages"),
    "dynamic_status": dynamic.get("status"),
    "monitoring_tier": dynamic.get("monitoring_tier"),
    "dynamic_error": dynamic.get("error"),
}, indent=2))
if dynamic.get("status") == "error":
    raise SystemExit("dynamic stage failed")
PY

echo "Report: $report"
