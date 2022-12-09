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
  project_id    = var.project_id
  repository_id = var.artifact_repository_id
}
module "gar" {
  source        = "../gar"
  project_id    = local.project_id
  repository_id = local.repository_id
}
module "wif" {
  source        = "../wif"
  project_id    = local.project_id
  repository_id = "bradegler/minty"
}
module "server_service_account" {
  source     = "../server-iam-secrets"
  project_id = local.project_id
}