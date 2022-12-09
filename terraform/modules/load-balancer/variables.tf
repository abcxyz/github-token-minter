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

variable "project_id" {
  type        = string
  description = "The project ID for the cloud project to create the workfload identity provider and pool"
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "The region to deploy the cloud run service in"
}

variable "service_name" {
  type        = string
  default     = "github-token-minter"
  description = "The name to give the load balancer"
}

variable "domain" {
  type        = string
  description = "The domain for tls certificates"
}