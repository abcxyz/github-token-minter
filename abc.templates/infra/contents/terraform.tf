terraform {
  required_version = ">= 1.0"

  backend "gcs" {
    bucket = "REPLACE_BUCKET_NAME"
    prefix = "REPLACE_BUCKET_PREFIX"
  }

  required_providers {
    google = {
      version = ">= 4.45"
      source  = "hashicorp/google"
    }
  }
}

provider "google" {
  user_project_override = true
}
