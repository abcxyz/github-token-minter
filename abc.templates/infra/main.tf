locals {
  project_id                        = "REPLACE_PROJECT_ID"
  automation_service_account_member = "REPLACE_AUTOMATION_SERVICE_ACCOUNT_MEMBER"
}

module "github_token_minter" {
  source = "git::https://github.com/abcxyz/github-token-minter.git//terraform?ref=f1144811e6f6583b9aa971189ca8f6ef0f947c8a"

  project_id = local.project_id

  domains    = ["REPLACE_DOMAINS"]
  dataset_id = "github_token_minter_audit_prod"

  wif_id = "token-minter"
  wif_github = {
    owner_id   = "REPLACE_GITHUB_OWNER_ID"
    owner_name = "REPLACE_GITHUB_OWNER_NAME"
    repo_id    = "REPLACE_GITHUB_REPO_ID"
    repo_name  = "REPLACE_GITHUB_REPO_NAME"
  }
  wif_attribute_condition   = "attribute.repository_owner_id == \"REPLACE_GITHUB_OWNER_ID\""
  ci_service_account_member = local.automation_service_account_member
}
