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
  description = "The project ID for the cloud project to create the artifact registry repository in"
}

variable "repository_id" {
  type        = string
  description = "The repostiry ID to name the artifact registry repository"
}

variable "registry_location" {
  type        = string
  default     = "us"
  description = "The location to create the artifact registry repository (defaults to 'us')"
}
