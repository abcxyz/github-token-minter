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

resource "google_logging_project_sink" "default" {
  project = var.project_id

  name        = format("%s-%s", var.log_sink_name, var.dataset_id)
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${var.dataset_id}"

  filter = <<-EOT
    LOG_ID("audit.abcxyz/activity") AND
    labels.service="${var.name}"
  EOT

  unique_writer_identity = true
  bigquery_options {
    use_partitioned_tables = true
  }

  depends_on = [
    google_project_service.default["logging.googleapis.com"],
  ]
}

resource "google_bigquery_dataset_iam_member" "bigquery_sink_memeber" {
  project = var.project_id

  dataset_id = google_bigquery_dataset.default.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.default.writer_identity
}
