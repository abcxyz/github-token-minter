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

data "google_project" "default" {
  project_id = var.project_id
}

resource "google_project_service" "default" {
  project = var.project_id
  for_each = toset([
    "cloudresourcemanager.googleapis.com",
    "bigquery.googleapis.com",
    "logging.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "run_service_account" {
  project      = data.google_project.default.project_id
  account_id   = "${var.name}-sa"
  display_name = "${var.name}-sa Cloud Run Service Account"
}

module "cloud_run" {
  source                = "git::https://github.com/abcxyz/terraform-modules.git//modules/cloud_run?ref=main"
  project_id            = data.google_project.default.project_id
  name                  = var.name
  image                 = var.image
  ingress               = "internal-and-cloud-load-balancing"
  secrets               = ["github-application-id", "github-installation-id", "github-privatekey"]
  service_account_email = google_service_account.run_service_account.email
  service_iam           = var.service_iam
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