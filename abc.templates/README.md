# GitHub Token Minter

## Installation with abc CLI

1. Render infrastructure template and actuate terraform.
```
abc templates render \
--dest infra/github-token-minter \
--input=automation_service_account_member=<SERVICE_ACCOUNT> \
--input=project_id=<PROJECT_ID> \
--input=domains=<COMMA_SEPARATED_DOMAINS> \
--input=terraform_state_bucket=<TERRAFORM_STATE_BUCKET> \
--input=terraform_state_prefix=<TERRAFORM_STATE_PREFIX> \
--input=github_owner_id=<GITHUB_ORG_ID> \
--input=github_owner_name=<GITHUB_ORG_NAME> \
--input=github_repo_id=<GITHUB_REPO_ID> \
--input=github_repo_name=<GITHUB_REPO_NAME> \
github.com/abcxyz/github-token-minter.git//abc.templates/infra?ref=<SHA>
```

