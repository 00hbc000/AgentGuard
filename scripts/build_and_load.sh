#!/usr/bin/env bash
# Build the sandbox + sink images and load them into the kind cluster.
# The tag is a content hash of sandbox/*, so unchanged code reuses existing images and the
# dashboard's Sandbox Scan finds exactly the same tag.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python}"
tag="$("$PYTHON" -m agentguard.cli prepare-sandbox)"
echo "Sandbox images ready with tag: ${tag}"
