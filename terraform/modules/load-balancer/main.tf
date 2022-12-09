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
  name    = "${local.name}-lb"
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
    service = google_cloud_run_service.default.name
  }

  depends_on = [google_project_service.project_services["compute.googleapis.com"]]
}