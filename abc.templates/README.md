# GitHub Token Minter

## Installation with abc CLI

1. Render infrastructure template and actuate terraform.
```shell
abc templates render \
-dest infra/github-token-minter \
-input=automation_service_account_member=<SERVICE_ACCOUNT> \
-input=project_id=<PROJECT_ID> \
-input=domain=<DOMAIN> \
-input=terraform_state_bucket=<TERRAFORM_STATE_BUCKET> \
-input=terraform_state_prefix=<TERRAFORM_STATE_PREFIX> \
-input=github_owner_id=<GITHUB_ORG_ID> \
github.com/abcxyz/github-token-minter.git//abc.templates/infra?ref=<TAG_OR_SHA>
```

A domain is required for GitHub Token Minter.


2. Render deployment image and workflows
```shell
abc templates render \
-input=wif_provider=<WIF_PROVIDER> \
-input=wif_service_account=<WIF_SERVICE_ACCOUNT> \
-input=docker_image_name=<DOCKER_IMAGE_NAME> \
-input=version=<VERSION_TAG> \
-input=service_name=<SERVICE_NAME> \
-input=project_id=<PROJECT_ID> \
-input=region=<REGION> \
github.com/abcxyz/github-token-minter.git//abc.templates/deployments?ref=<TAG_OR_SHA>
```
