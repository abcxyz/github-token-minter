# GitHub Token Minter

## Installation with abc CLI

1. Render infrastructure template and actuate terraform.
> A domain is required for GitHub Token Minter.
```shell
abc templates render \
-input=automation_service_account_member=<SERVICE_ACCOUNT> \
-input=project_id=<PROJECT_ID> \
-input=domain=<DOMAIN> \
-input=terraform_state_bucket=<TERRAFORM_STATE_BUCKET> \
-input=terraform_state_prefix=<TERRAFORM_STATE_PREFIX> \
-input=github_owner_id=<GITHUB_ORG_ID> \
github.com/abcxyz/github-token-minter.git//abc.templates/infra?ref=<TAG_OR_SHA>
```
2. After acutation, update the DNS record with the IP address of the load balancer.
3. With elevated permissions, update the `github-privatekey`, `github-installation-id`, and `github-application-id` in Secret Manager.
4. Grant the Cloud Run service agent `read` permissions to pull from the designated artifact registry repository, with `roles/artifactregistry.reader`.
5. Render deployment image and workflows.
```shell
abc templates render \
-input=wif_provider=<WIF_PROVIDER> \
-input=wif_service_account=<WIF_SERVICE_ACCOUNT> \
-input=docker_image_name=<DOCKER_IMAGE_NAME> \
-input=version=<VERSION_TAG> \
-input=service_name=<SERVICE_NAME> \
-input=project_id=<PROJECT_ID> \
-input=region=<REGION> \
-input=github_owner_name=<GITHUB_ORG> \
github.com/abcxyz/github-token-minter.git//abc.templates/deployments?ref=<TAG_OR_SHA>
```
6. Add configurations in `deployments/configs/<github_owner_name>` for each repository.
7. Run the deployment workflow.
