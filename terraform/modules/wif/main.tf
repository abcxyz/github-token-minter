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
  project_id = var.project_id
  repo       = var.repository_id

  services = [
    "iamcredentials.googleapis.com",
  ]
}

resource "google_project_service" "project_services" {
  project            = local.project_id
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "wif_service_account" {
  account_id   = "github-wif-sa"
  display_name = "GitHub WIF Service Account"
}

resource "google_iam_workload_identity_pool" "wif_github_pool" {
  project                   = local.project_id
  workload_identity_pool_id = "wif-github-pool"
  display_name              = "WIF Pool for GitHub CI access"
  description               = "Identity pool for CI environment"

  depends_on = [
    google_project_service.project_services,
  ]
}

resource "google_iam_workload_identity_pool_provider" "wif_github_provider" {
  project                            = local.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.wif_github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "wif-github-provider"
  display_name                       = "GitHub provider"
  description                        = "OIDC identity pool provider for CI environment"
  attribute_mapping = {
    "google.subject"       = "assertion.sub",
    "attribute.actor"      = "assertion.actor",
    "attribute.repository" = "assertion.repository",
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  depends_on = [
    google_iam_workload_identity_pool.wif_github_pool
  ]
}

data "google_iam_policy" "pool_policy" {
  binding {
    role = "roles/iam.workloadIdentityUser"

    members = [
      format("principalSet://iam.googleapis.com/%s/attribute.repository/%s",
        google_iam_workload_identity_pool.wif_github_pool.workload_identity_pool_id,
      local.repo)
    ]
  }
}

resource "google_service_account_iam_policy" "wif-service-account-iam" {
  service_account_id = google_service_account.wif_service_account.name
  policy_data        = data.google_iam_policy.pool_policy.policy_data

  depends_on = [
    google_service_account.wif_service_account
  ]
}
