# Terraform Directory

This directory contains the Terraform configuration for deploying `github-token-minter` on Google Cloud Platform.

## Purpose

The `terraform` package is used to:
- Enable required Google Cloud services.
- Deploy the service to Cloud Run.
- Set up a service account for the Cloud Run service.
- Optionally set up a Global Cloud Load Balancer.
- Optionally set up Workload Identity Federation for GitHub Actions.
- Set up monitoring alerts (defined in `alerts.tf`).

## Files

- **`main.tf`**: Core deployment configuration (Cloud Run, Service Account, Load Balancer).
- **`github-wif.tf`**: Configuration for Workload Identity Federation.
- **`alerts.tf`**: Configuration for monitoring alerts.
- **`terraform.tf`**: Terraform settings (providers, backend).
- **`variables.tf`**: Variable definitions.
- **`outputs.tf`**: Output definitions.
