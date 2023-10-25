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

resource "google_project_service" "default" {
  for_each = toset([
    "cloudresourcemanager.googleapis.com",
    "bigquery.googleapis.com",
    "logging.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "serviceusage.googleapis.com",
    "sts.googleapis.com",
  ])

  project = var.project_id

  service                    = each.value
  disable_on_destroy         = false
  disable_dependent_services = false # To keep, or not to keep? From github-wif module
}

resource "google_service_account" "run_service_account" {
  project = var.project_id

  account_id   = "${var.name}-sa"
  display_name = "${var.name}-sa Cloud Run Service Account"
}

module "gclb" {
  count = var.enable_gclb ? 1 : 0

  source = "git::https://github.com/abcxyz/terraform-modules.git//modules/gclb_cloud_run_backend?ref=46d3ffd82d7c3080bc5ec2cc788fe3e21176a8be"

  project_id = var.project_id

  name             = var.name
  run_service_name = module.cloud_run.service_name
  domains          = var.domains
}

module "cloud_run" {
  source = "git::https://github.com/abcxyz/terraform-modules.git//modules/cloud_run?ref=e7f268b6a29e130eb81e2b7250f6b67a9ae03bd3"

  project_id = var.project_id

  name                  = var.name
  image                 = var.image
  ingress               = var.enable_gclb ? "internal-and-cloud-load-balancing" : "all"
  min_instances         = 1
  secrets               = ["github-application-id", "github-installation-id", "github-privatekey"]
  service_account_email = google_service_account.run_service_account.email
  service_iam = {
    admins     = var.service_iam.admins
    developers = toset(concat(var.service_iam.developers, [var.ci_service_account_member]))
    invokers   = toset(concat(var.service_iam.invokers, [google_service_account.wif_service_account.member]))
  }

  secret_envvars = {
    "GITHUB_APP_ID" : {
      name : "github-application-id",
      version : "latest",
    },
    "GITHUB_INSTALL_ID" : {
      name : "github-installation-id",
      version : "latest",
    },
    "GITHUB_PRIVATE_KEY" : {
      name : "github-privatekey",
      version : "latest",
    }
  }
}

# allow the ci service account to act as the cloud run service account
# this allows the ci service account to deploy new revisions for the
# cloud run sevice
resource "google_service_account_iam_member" "run_sa_ci_binding" {
  service_account_id = google_service_account.run_service_account.name
  role               = "roles/iam.serviceAccountUser"
  member             = var.ci_service_account_member
}

