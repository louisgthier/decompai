#!/usr/bin/env bash
set -euo pipefail

APP_IMAGE="${DECOMPAI_APP_IMAGE:-louisgauthier/decompai:1.0.0}"
RUNNER_IMAGE="${DECOMPAI_RUNNER_IMAGE:-louisgauthier/decompai-runner:1.0.0}"
PLATFORM="${DOCKER_BUILD_PLATFORM:-linux/amd64}"

if [[ -z "${DOCKER_USERNAME:-}" ]]; then
  echo "[publish-images] DOCKER_USERNAME not set; docker login will be skipped." >&2
else
  echo "[publish-images] Logging into Docker Hub as ${DOCKER_USERNAME}"
  echo "${DOCKER_PASSWORD:-}" | docker login --username "${DOCKER_USERNAME}" --password-stdin
fi

echo "[publish-images] Building app image ${APP_IMAGE}"
docker buildx build --platform "${PLATFORM}" -f Dockerfile -t "${APP_IMAGE}" . --push

echo "[publish-images] Building runner image ${RUNNER_IMAGE}"
docker buildx build --platform "${PLATFORM}" -f Dockerfile.runner -t "${RUNNER_IMAGE}" . --push

echo "[publish-images] Done."
