locals {
  project_id                        = "REPLACE_PROJECT_ID"
  automation_service_account_member = "REPLACE_AUTOMATION_SERVICE_ACCOUNT_MEMBER"
}

module "github_token_minter" {
  source = "git::https://github.com/abcxyz/github-token-minter.git//terraform?ref=ad64bba9b86b89557384fadf630856b4b13b2567"

  project_id = local.project_id

  domains    = ["REPLACE_DOMAINS"]
  dataset_id = "github_token_minter_audit_prod"
  service_iam = {
    admins     = []
    developers = [local.automation_service_account_member] # ci service account
    invokers   = []
  }
}
