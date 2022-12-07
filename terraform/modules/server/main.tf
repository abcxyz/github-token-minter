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
  region        = var.region
  service_name  = var.service_name
  service_image = var.service_image
  services = [
    "monitoring.googleapis.com",
    "run.googleapis.com",
    "stackdriver.googleapis.com",
  ]
}

resource "google_project_service" "project_services" {
  project            = local.project_id
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}

resource "google_cloud_run_service" "server" {
  name     = local.service_name
  location = local.region
  project  = local.project_id

  template {
    spec {
      containers {
        image = local.service_image

        resources {
          limits = {
            memory = "1G"
          }
        }

      }
    }
  }

  depends_on = [
    google_project_service.project_services
  ]
}
