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
