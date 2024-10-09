locals {
  # time helpers
  second = 1
  minute = 60 * local.second
  hour   = 60 * local.minute
  day    = 24 * local.hour

  # runbooks
  runbook_url_prefix = "https://github.com/abcxyz/github-token-minter/blob/main/docs/playbooks/alerts"

  # cloud run error logs
  request_failure      = "The request failed because either the HTTP response was malformed or connection to the instance had an error."
  auto_scaling_failure = "The request was aborted because there was no available instance."

  error_severity = "ERROR"

  log_name_suffix_requests = "requests"

  default_threshold_ms               = 5 * 1000
  default_utilization_threshold_rate = 0.8

  default_log_based_condition_threshold = {
    window    = 5 * local.minute
    threshold = 0
  }

  service_window = 30 * local.minute
}

resource "google_monitoring_notification_channel" "non_paging" {
  for_each = var.alerts.channels_non_paging

  project = var.project_id

  display_name = "Non-paging Notification Channel"
  type         = each.key
  labels       = each.value.labels
}


module "cloud_run_alerts" {
  count = var.alerts.enabled ? 1 : 0

  source = "git::https://github.com/abcxyz/terraform-modules.git//modules/alerts_cloud_run?ref=597217bd226277c83de53fb426144f60d4708625"

  project_id = var.project_id

  notification_channels_non_paging            = [for x in values(google_monitoring_notification_channel.non_paging) : x.id]
  enable_built_in_forward_progress_indicators = true
  enable_built_in_container_indicators        = true
  enable_log_based_text_indicators            = true

  cloud_run_resource = {
    service_name = module.cloud_run.service_name
  }
  runbook_urls = {
    forward_progress = "${local.runbook_url_prefix}/ForwardProgressFailed.md"
    container_util   = "${local.runbook_url_prefix}/ContainerUsage.md"
    bad_request      = "${local.runbook_url_prefix}/BadRequests.md"
    server_fault     = "${local.runbook_url_prefix}/ServerFaults.md"
    request_latency  = "${local.runbook_url_prefix}/RequestLatency.md"
  }

  built_in_forward_progress_indicators = {
    "request-count" = {
      metric             = "request_count"
      window             = local.service_window
      threshold          = 1
      additional_filters = "metric.label.response_code_class=\"2xx\""
    },
  }

  built_in_container_util_indicators = {
    "cpu" = {
      metric    = "container/cpu/utilizations"
      window    = local.service_window
      threshold = local.default_utilization_threshold_rate
      p_value   = 99
    },
    "memory" = {
      metric    = "container/memory/utilizations"
      window    = local.service_window
      threshold = local.default_utilization_threshold_rate
      p_value   = 99
    },
    "all-container-count" = {
      metric    = "container/instance_count"
      window    = local.service_window
      threshold = 10
    },
  }

  log_based_text_indicators = {
    "scaling-failure" = {
      log_name_suffix      = local.log_name_suffix_requests
      severity             = local.error_severity
      text_payload_message = local.auto_scaling_failure
      condition_threshold  = local.default_log_based_condition_threshold
    },
    "failed-request" : {
      log_name_suffix      = local.log_name_suffix_requests
      severity             = local.error_severity
      text_payload_message = local.request_failure,
      condition_threshold  = local.default_log_based_condition_threshold
    },
  }

  service_4xx_configuration = {
    enabled   = true
    window    = local.service_window
    threshold = local.default_threshold_ms
  }

  service_5xx_configuration = {
    enabled   = true
    window    = local.service_window
    threshold = local.default_threshold_ms
  }

  service_latency_configuration = {
    enabled   = true
    window    = local.service_window
    threshold = local.default_threshold_ms
    p_value   = 99
  }

  service_max_conns_configuration = {
    enabled   = true
    window    = local.service_window
    threshold = 60
    p_value   = 99
  }
}
