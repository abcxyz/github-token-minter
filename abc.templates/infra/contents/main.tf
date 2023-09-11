locals {
  project_id                        = "REPLACE_PROJECT_ID"
  automation_service_account_member = "REPLACE_AUTOMATION_SERVICE_ACCOUNT_MEMBER"
}

module "github_token_minter" {
  source = "git::https://github.com/abcxyz/github-token-minter.git//terraform?ref=v0.0.12"

  project_id = local.project_id

  domains    = ["REPLACE_DOMAIN"]
  dataset_id = "github_token_minter_audit_prod"

  github_owner_id           = "REPLACE_GITHUB_OWNER_ID"
  ci_service_account_member = local.automation_service_account_member
}
