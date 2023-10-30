#!/usr/bin/env bash
set -euo pipefail

GITHUB_TOKEN_MINTER_VERSION='v0.0.16'
PLATFORM='amd64'
IMAGE_NAME="REPLACE_FULL_IMAGE_NAME:${GITHUB_TOKEN_MINTER_VERSION}-${GITHUB_SHA}"

docker build -t "${IMAGE_NAME}" \
  --build-arg="VERSION=${GITHUB_TOKEN_MINTER_VERSION}-${PLATFORM}" \
  REPLACE_SUBDIRECTORY

docker push "${IMAGE_NAME}"

gcloud run services update "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${IMAGE_NAME}"
