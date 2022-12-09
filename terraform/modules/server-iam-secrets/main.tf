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
  project_id           = var.project_id
  service_account_name = var.service_account_name

  roles = [
    "roles/cloudtrace.agent",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/stackdriver.resourceMetadata.writer",
  ]

  secrets = [
    "github-application-id",
    "github-installation-id",
    "github-privatekey"
  ]
}


resource "google_service_account" "server_service_account" {
  project      = local.project_id
  account_id   = local.service_account_name
  display_name = "GitHub Token Minter Server Service Account"
}

resource "google_project_iam_member" "server_roles" {
  for_each = toset(local.roles)

  project = local.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.server_service_account.email}"
}

resource "google_secret_manager_secret" "server_secrets" {
  for_each = toset(local.secrets)

  project   = local.project_id
  secret_id = each.key
  replication {
    automatic = true
  }
}

resource "google_project_iam_member" "sa_secret_binding" {
  project = local.project_id
  member  = "serviceAccount:${google_service_account.server_service_account.email}"
  role    = "roles/secretmanager.secretAccessor"
}