output "gclb_external_ip_name" {
  description = "The external IPv4 name assigned to the global fowarding rule for the global load balancer."
  value       = module.github_token_minter.gclb_external_ip_name
}

output "gclb_external_ip_address" {
  description = "The external IPv4 assigned to the global fowarding rule for the global load balancer."
  value       = module.github_token_minter.gclb_external_ip_address
}

output "run_service_name" {
  description = "The Cloud Run service name."
  value       = module.github_token_minter.run_service_name
}

output "run_service_url" {
  description = "The Cloud Run service url."
  value       = module.github_token_minter.run_service_url
}

output "wif_pool" {
  value = module.github_token_minter.wif_pool
}

output "wif_provider" {
  value = module.github_token_minter.wif_provider
}

output "wif_service_account_email" {
  value = module.github_token_minter.wif_service_account_email
}

output "wif_service_account_member" {
  value = module.github_token_minter.wif_service_account_member
}
