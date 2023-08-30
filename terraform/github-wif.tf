# Copyright 2023 The Authors (see AUTHORS file)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

locals {
  wif_attribute_mapping = {
    "google.subject" : "assertion.sub"
    "attribute.actor" : "assertion.actor"
    "attribute.aud" : "assertion.aud"
    "attribute.repository_owner_id" : "assertion.repository_owner_id"
  }
  wif_attribute_condition = "attribute.repository_owner_id == \"${var.github_owner_id}\""
}

resource "google_iam_workload_identity_pool" "default" {
  project = var.project_id

  workload_identity_pool_id = "github-token-minter" # 32 characters
  display_name              = "Token-Minter WIF pool"                    # 32 characters
  description               = "Token-Minter OIDC identity pool"

  depends_on = [
    google_project_service.default["iam.googleapis.com"],
  ]
}

resource "google_iam_workload_identity_pool_provider" "default" {
  project = var.project_id

  workload_identity_pool_id          = google_iam_workload_identity_pool.default.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-token-minter" # 32 characters
  display_name                       = "Token-Minter WIF Provider"                # 32 characters
  description                        = "Token-Minter OIDC identity provider"

  attribute_mapping   = local.wif_attribute_mapping
  attribute_condition = local.wif_attribute_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "wif_service_account" {
  project = var.project_id

  account_id   = "github-token-minter-sa" # 30 characters
  display_name = "Token Minter WIF service account"
}

resource "google_service_account_iam_member" "default" {
  service_account_id = google_service_account.wif_service_account.id
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.default.name}/*"
}

