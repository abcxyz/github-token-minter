// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

locals {
  project_id        = var.project_id
  repository_id     = var.repository_id
  registry_location = var.registry_location

  services = [
    "serviceusage.googleapis.com",
    "artifactregistry.googleapis.com",
    "iamcredentials.googleapis.com",
  ]
}

resource "google_project_service" "project_services" {
  project            = local.project_id
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "artifact_repository" {
  provider = google-beta

  location      = local.registry_location
  project       = local.project_id
  repository_id = local.repository_id
  description   = "Container registry for docker images."
  format        = "DOCKER"

  depends_on = [
    google_project_service.project_services,
  ]
}
