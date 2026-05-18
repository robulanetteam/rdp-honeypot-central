#!/usr/bin/env bash
# Builds and pushes the honeypot-central Docker image to a registry.
#
# Usage:
#   bash build-push.sh                       # Docker Hub: youruser/honeypot-central
#   IMAGE=ghcr.io/youruser/honeypot-central bash build-push.sh
#   IMAGE=registry.example.com/hp-central PLATFORMS=linux/amd64 bash build-push.sh
#
# Env vars:
#   IMAGE       – full image name without tag   (default: honeypot-central)
#   TAG         – tag to apply                  (default: latest)
#   PLATFORMS   – comma-separated target archs  (default: linux/amd64,linux/arm64)
#   PUSH        – set to 0 to build only, skip push

set -euo pipefail

IMAGE="${IMAGE:-honeypot-central}"
TAG="${TAG:-latest}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
PUSH="${PUSH:-1}"

FULL="${IMAGE}:${TAG}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Building ${FULL}  (${PLATFORMS})"

# Ensure buildx builder with multi-arch support exists
if ! docker buildx inspect hp-central-builder &>/dev/null; then
    docker buildx create --name hp-central-builder --driver docker-container --use
else
    docker buildx use hp-central-builder
fi
docker buildx inspect --bootstrap hp-central-builder

BUILD_CMD=(
    docker buildx build
    --platform "${PLATFORMS}"
    --tag "${FULL}"
    --file "${SCRIPT_DIR}/Dockerfile"
)

# Also tag as :latest if TAG is a version number
if [[ "${TAG}" != "latest" ]]; then
    BUILD_CMD+=(--tag "${IMAGE}:latest")
fi

if [[ "${PUSH}" == "1" ]]; then
    BUILD_CMD+=(--push)
    echo "==> Will push to registry"
else
    BUILD_CMD+=(--load)
    echo "==> Local build only (PUSH=0)"
fi

BUILD_CMD+=("${SCRIPT_DIR}")
"${BUILD_CMD[@]}"

echo ""
echo "==> Done: ${FULL}"
if [[ "${PUSH}" == "1" ]]; then
    echo "    Pull with:  docker pull ${FULL}"
fi
