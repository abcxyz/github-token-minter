locals {
  project_id                        = "REPLACE_PROJECT_ID"
  automation_service_account_member = "REPLACE_AUTOMATION_SERVICE_ACCOUNT_MEMBER"
}

resource "google_project_service" "services" {
  for_each = toset([
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
  ])

  project = local.project_id

  service                    = each.value
  disable_on_destroy         = false
  disable_dependent_services = false
}

module "github_token_minter_github_wif" {
  source = "git::https://github.com/abcxyz/github-token-minter.git//terraform/modules?ref=1070deb5614f6c8edac14ec3b8496f2e28e2eea3"

  project_id = local.project_id

  id = "token-minter"
  github = {
    owner_id   = "REPLACE_GITHUB_OWNER_ID"
    owner_name = "REPLACE_GITHUB_OWNER_NAME"
    repo_id    = "REPLACE_GITHUB_REPO_ID"
    repo_name  = "REPLACE_GITHUB_REPO_NAME"
  }
  wif_attribute_condition = "attribute.repository_owner_id == \"REPLACE_GITHUB_OWNER_ID\""
}

module "github_token_minter" {
  source = "git::https://github.com/abcxyz/github-token-minter.git//terraform?ref=1070deb5614f6c8edac14ec3b8496f2e28e2eea3"

  project_id = local.project_id

  domains    = ["REPLACE_DOMAINS"]
  dataset_id = "github_token_minter_audit_prod"
  invoker_service_account_member = module.github_token_minter_github_wif.service_account_member
  service_iam = {
    admins     = []
    developers = [local.automation_service_account_member] # ci service account
    invokers   = [module.github_token_minter_github_wif.service_account_member] # GitHub OIDC access only
  }
}
