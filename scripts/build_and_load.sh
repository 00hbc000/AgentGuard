#!/usr/bin/env bash
set -euo pipefail

cluster="${AGENTGUARD_KIND_CLUSTER:-agentguard}"
tag="${AGENTGUARD_IMAGE_TAG:-$(git rev-parse --short HEAD)-$(date +%s)}"

docker build --build-arg AGENTGUARD_BUILD_TAG="$tag" -t "agentguard-sandbox:$tag" sandbox
docker build --build-arg AGENTGUARD_BUILD_TAG="$tag" -f sandbox/Sink.Dockerfile -t "agentguard-sink:$tag" sandbox
kind load docker-image "agentguard-sandbox:$tag" --name "$cluster"
kind load docker-image "agentguard-sink:$tag" --name "$cluster"
docker exec "${cluster}-control-plane" crictl images | grep -E "agentguard-(sandbox|sink).*${tag}"
printf '%s\n' "$tag"
