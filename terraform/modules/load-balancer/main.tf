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
  service_name = var.service_name
  region       = var.region
  domain       = var.domain
  project_id   = var.project_id

  services = [
    "compute.googleapis.com",
  ]
}

resource "google_project_service" "project_services" {
  project            = local.project_id
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}


module "lb_http" {
  source  = "GoogleCloudPlatform/lb-http/google//modules/serverless_negs"
  version = "~> 6.3"
  name    = "${local.service_name}-lb"
  project = local.project_id

  ssl                             = true
  managed_ssl_certificate_domains = [local.domain]
  https_redirect                  = true

  backends = {
    "${local.name}" = {
      description = null
      groups = [
        {
          group = google_compute_region_network_endpoint_group.default.id
        }
      ]
      enable_cdn              = false
      security_policy         = null
      custom_request_headers  = null
      custom_response_headers = null

      iap_config = {
        enable               = false
        oauth2_client_id     = ""
        oauth2_client_secret = ""
      }
      log_config = {
        enable      = false
        sample_rate = null
      }
    }
  }

  depends_on = [google_project_service.project_services["compute.googleapis.com"]]
}

resource "google_compute_region_network_endpoint_group" "default" {
  provider              = google-beta
  project               = local.project_id
  region                = local.region
  name                  = "${local.name}-neg"
  network_endpoint_type = "SERVERLESS"
  cloud_run {
    service = local.service_name
  }

  depends_on = [google_project_service.project_services["compute.googleapis.com"]]
}