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
    "attribute.enterprise_id" : "assertion.enterprise_id"
  }
  wif_attr_org_id        = var.github_owner_id != "" ? "attribute.repository_owner_id == \"${var.github_owner_id}\"" : ""
  wif_attr_enterprise_id = var.github_enterprise_id != "" ? "attribute.enterprise_id == \"${var.github_enterprise_id}\"" : ""

}

resource "google_iam_workload_identity_pool" "default" {
  count = var.enable_wif ? 1 : 0

  project = var.project_id

  workload_identity_pool_id = var.name               # 32 characters
  display_name              = "${var.name} WIF pool" # 32 characters
  description               = "${var.name} OIDC identity pool"

  depends_on = [
    google_project_service.default["iam.googleapis.com"],
  ]
}

resource "google_iam_workload_identity_pool_provider" "default" {
  count = var.enable_wif ? 1 : 0

  project = var.project_id

  workload_identity_pool_id          = google_iam_workload_identity_pool.default[0].workload_identity_pool_id
  workload_identity_pool_provider_id = var.name                   # 32 characters
  display_name                       = "${var.name} WIF Provider" # 32 characters
  description                        = "${var.name} OIDC identity provider"

  attribute_mapping   = local.wif_attribute_mapping
  attribute_condition = join(" && ", compact([local.wif_attr_enterprise_id, local.wif_attr_org_id]))

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "wif_service_account" {
  count = var.enable_wif ? 1 : 0

  project = var.project_id

  account_id   = "${var.name}-wif-sa" # 30 characters
  display_name = "${var.name} WIF service account"
}

resource "google_service_account_iam_member" "default" {
  count = var.enable_wif ? 1 : 0

  service_account_id = google_service_account.wif_service_account[0].id
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.default[0].name}/*"
}

