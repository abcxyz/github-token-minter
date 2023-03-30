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

variable "dataset_editor_service_account_member" {
  type        = string
  description = "The service account that will be used to invoke the Cloud Run service that needs to be able to edit the BQ dataset."
}

variable "log_sink_name" {
  type        = string
  default     = "github-token-minter-logs"
  description = "The log sink name that filters for audit logs."
}

variable "domain" {
  description = "Domain name for the Google Cloud Load Balancer."
  type        = string
}
