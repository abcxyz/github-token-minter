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
  project_id            = var.project_id
  region                = var.region
  service_name          = var.service_name
  service_image         = var.service_image
  service_account_email = var.service_account_email
  default_server_revision_annotations = {
    "autoscaling.knative.dev/maxScale" : "10",
    "run.googleapis.com/sandbox" : "gvisor"
  }
  default_server_service_annotations = {
    "run.googleapis.com/ingress" : "internal"
    "run.googleapis.com/launch-stage" : "BETA"
  }
  default_server_env_vars = {
    # At the moment we don't have any default env vars.
  }
  services = [
    "monitoring.googleapis.com",
    "run.googleapis.com",
    "stackdriver.googleapis.com",
  ]

  secrets = {
    "GITHUB_APP_ID" : [var.application_id_secret_name, var.application_id_secret_version],
    "GITHUB_INSTALL_ID" : [var.installation_id_secret_name, var.installation_id_secret_version],
    "GITHUB_PRIVATE_KEY" : [var.privatekey_secret_name, var.privatekey_secret_version]
  }
}

resource "google_project_service" "project_services" {
  project            = local.project_id
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}

resource "google_cloud_run_service" "server" {
  name                       = local.service_name
  location                   = local.region
  project                    = local.project_id
  autogenerate_revision_name = true

  metadata {
    annotations = local.default_server_service_annotations
  }

  template {
    spec {
      service_account_name = local.service_account_email
      containers {
        image = local.service_image

        resources {
          limits = {
            memory = "1G"
          }
        }
        dynamic "env" {
          for_each = local.secrets

          content {
            name = env.key
            value_from {
              secret_key_ref {

                key  = env.value[0]
                name = env.value[1]
              }
            }
          }
        }

      }
    }

    metadata {
      annotations = local.default_server_revision_annotations
    }

  }

  lifecycle {
    ignore_changes = [
      metadata[0].annotations["client.knative.dev/user-image"],
      metadata[0].annotations["run.googleapis.com/client-name"],
      metadata[0].annotations["run.googleapis.com/client-version"],
      metadata[0].annotations["run.googleapis.com/ingress-status"],
      metadata[0].annotations["serving.knative.dev/creator"],
      metadata[0].annotations["serving.knative.dev/lastModifier"],
      metadata[0].labels["cloud.googleapis.com/location"],
      template[0].metadata[0].annotations["client.knative.dev/user-image"],
      template[0].metadata[0].annotations["run.googleapis.com/client-name"],
      template[0].metadata[0].annotations["run.googleapis.com/client-version"],
      template[0].metadata[0].annotations["serving.knative.dev/creator"],
      template[0].metadata[0].annotations["serving.knative.dev/lastModifier"],
    ]
  }

  depends_on = [
    google_project_service.project_services
  ]
}
