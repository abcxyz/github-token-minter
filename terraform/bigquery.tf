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

resource "google_bigquery_dataset" "default" {
  project    = data.google_project.default.project_id
  dataset_id = var.dataset_id
  location   = var.dataset_location

  depends_on = [
    google_project_service.default["bigquery.googleapis.com"]
  ]
}

resource "google_bigquery_dataset_iam_binding" "owners" {
  project    = data.google_project.default.project_id
  dataset_id = google_bigquery_dataset.default.dataset_id
  role       = "roles/bigquery.dataOwner"
  members    = toset(var.dataset_iam.owners)
}

resource "google_bigquery_dataset_iam_binding" "editors" {
  project    = data.google_project.default.project_id
  dataset_id = google_bigquery_dataset.default.dataset_id
  role       = "roles/bigquery.dataEditor"
  members    = toset(var.dataset_iam.editors)
}

resource "google_bigquery_dataset_iam_binding" "viewers" {
  project    = data.google_project.default.project_id
  dataset_id = google_bigquery_dataset.default.dataset_id
  role       = "roles/bigquery.dataViewer"
  members    = toset(var.dataset_iam.viewers)
}
