terraform {
  backend "gcs" {
    bucket = "REPLACE_BUCKET_NAME"
    prefix = "REPLACE_BUCKET_PREFIX"
  }
}
