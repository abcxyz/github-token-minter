#!/usr/bin/env bash
set -euo pipefail

# Expected to be set externally.
declare -r GITHUB_SHA SERVICE_NAME PROJECT_ID REGION

GITHUB_TOKEN_MINTER_VERSION='REPLACE_VERSION_TAG'
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
