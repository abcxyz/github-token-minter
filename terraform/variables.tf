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

variable "project_id" {
  description = "The GCP project ID."
  type        = string
  validation {
    condition     = length(var.project_id) <= 30
    error_message = "ERROR: project_id must be <= 30 characters."
  }
}

variable "name" {
  description = "The name of this component."
  type        = string
  default     = "github-token-minter"
  validation {
    condition     = can(regex("^[A-Za-z][0-9A-Za-z-]+[0-9A-Za-z]$", var.name))
    error_message = "Name can only contain letters, numbers, hyphens(-) and must start with letter."
  }
}

# This current approach allows the end-user to disable the GCLB in favor of calling the Cloud Run service directly.
# This was done to use tagged revision URLs for integration testing on multiple pull requests.
variable "enable_gclb" {
  description = "Enable the use of a Google Cloud load balancer for the Cloud Run service. By default this is true, this should only be used for integration environments where services will use tagged revision URLs for testing."
  type        = bool
  default     = true
}

variable "domains" {
  description = "Domain names for the Google Cloud Load Balancer."
  type        = list(string)
}

variable "image" {
  description = "Cloud Run service image name to deploy."
  type        = string
  default     = "gcr.io/cloudrun/hello:latest"
}

variable "service_iam" {
  description = "IAM member bindings for the Cloud Run service."
  type = object({
    admins     = list(string)
    developers = list(string)
    invokers   = list(string)
  })
  default = {
    admins     = []
    developers = []
    invokers   = []
  }
}

variable "dataset_location" {
  type        = string
  description = "The BigQuery dataset location."
  default     = "US"
}

variable "dataset_id" {
  type        = string
  description = "The BigQuery dataset id to create."
}

variable "log_sink_name" {
  type        = string
  default     = "github-token-minter-logs"
  description = "The log sink name that filters for audit logs."
}

variable "ci_service_account_member" {
  type        = string
  description = "The service account member for deploying revisions to Cloud Run"
}

variable "wif_id" {
  description = "An ID for these resources."
  type        = string
  validation {
    condition     = length(var.wif_id) <= 22
    error_message = "ERROR: id must be 22 characters or less."
  }
}

variable "wif_github" {
  description = "The GitHub repository information."
  type = object({
    owner_name     = string
    owner_id       = string
    repo_name      = string
    repo_id        = string
    default_branch = optional(string, "main")
  })
}

variable "wif_attribute_mapping" {
  type        = map(string)
  description = "(Optional) Workload Identity Federation provider attribute mappings. Defaults to base mapping for default attribute condition."
  default     = null
}

variable "wif_attribute_condition" {
  type        = string
  description = "(Optional) Workload Identity Federation provider attribute condition. Appended to base condition, matching GitHub owner and repository id. Defaults to preventing `pull_request_target` event and matching GitHub owner and repository id."
  default     = null
}
