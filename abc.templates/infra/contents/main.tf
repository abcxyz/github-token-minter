locals {
  project_id                        = "REPLACE_PROJECT_ID"
  automation_service_account_member = "REPLACE_AUTOMATION_SERVICE_ACCOUNT_MEMBER"
}

module "REPLACE_MODULE_NAME" {
  source = "git::https://github.com/abcxyz/github-token-minter.git//terraform?ref=REPLACE_VERSION_SHA" # REPLACE_VERSION_TAG

  project_id = local.project_id

  name    = "REPLACE_CUSTOM_NAME"
  domains = ["REPLACE_DOMAIN"]

  github_owner_id           = "REPLACE_GITHUB_OWNER_ID"
  ci_service_account_member = local.automation_service_account_member
}
