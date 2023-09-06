#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME=REPLACE_FULL_IMAGE_NAME:REPLACE_VERSION

docker build -t "${IMAGE_NAME}" REPLACE_SUBDIRECTORY

docker push "${IMAGE_NAME}"

gcloud run services update "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${IMAGE_NAME}"
