output "wif_pool" {
  value = google_iam_workload_identity_pool.default.name
}

output "wif_provider" {
  value = google_iam_workload_identity_pool_provider.default.name
}

output "service_account_email" {
  value = google_service_account.default.email
}

output "service_account_member" {
  value = google_service_account.default.member
}
