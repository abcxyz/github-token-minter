# Migration Guide v2.0

The changes made in version 2.0 to the configuration file structure force users to modify their existing configurations and move them into the new deployment locations. This guide will help to outline that process.

If you deploy version 2.0+ in the same way that you deploy legacy versions v0.x they will work out of the box. The v2.0 server supports reading legacy configuration files and can be used without the direct scope targetting. However, this negates some of the benefits of decentralized configuration including requiring the deployer to rebuild the container with all configuration files stored locally.

## Deploy v2.0

The first step to get the new container deployed into your environment with no other changes. Use the same container build process used in v0.x deployments with the same configuration files. This ensures that you can get the container itself running and you aren't changing multiple variables simultaneously.

## Configuration Files

The main change in v2.0 is the decentralization of configuration files. The long term goal is to migrate all configurations out of the container allowing users to make configuration updates without requiring the rebuilding and redeployment of the `github-token-minter` server.

Details about the new configuration file structure can be found in the main [README.md](../../README.md).

**NOTE:** We recommend a phase rollout where one configuration file is replaced at tested at a time. This helps to keep your environment stable while you migrate.

Previously, configuration files were stored in a centralized repository and added into the container as local files at deployment time. GitHub Token Minter v2 creates a more decentralized configuration approach by moving these files into the target repository allowing configurations to change out of band from deployments.

### Example

Let's say you have a configuration file for a repository under the `foo` org called `bar.yaml`. This file would have been stored in a repository somewhere in a directory structure like `ghtm/configs/foo/bar.yaml`. This file should now live in the repository `foo/bar/.github/minty.yaml`.

### Migration

Let's start with a typical v0.x configuration file to use as an example:

```yaml
# abcxyz/github-token-minter.yaml
- if: |-
    assertion.workflow_ref.startsWith("abcxyz/github-token-minter/.github/workflows/ci.yml")
  repositories:
    - 'github-token-minter'
  permissions:
    issues: 'read'

- if: |-
    assertion.workflow_ref == 'abcxyz/github-token-minter/.github/workflows/create-tag.yml@refs/heads/main' &&
    assertion.job_workflow_ref == 'abcxyz/pkg/.github/workflows/create-tag.yml@refs/heads/main' &&
    assertion.event_name == 'workflow_dispatch'
  repositories:
    - 'github-token-minter'
  permissions:
    contents: 'write'
```

In v0.x this file was read top to bottom attempting to match each rule in sequence. In v2.0 we skip this scanning in favor of targetted scopes.

First we want to define the config file version and a top level rule that prevents other orgs and repositories from requesting permissions on this repository.

```yaml
version: 'minty.abcxyz.dev/v2'

rule:
  if: |-
      assertion.iss == issuers.github &&
      assertion.repository_owner_id == '93787867' &&
      assertion.repository_id == '576289489'
```

That top level rule states that we only accept tokens issued by github that come from the `abcxyz` oganization (identified by id) and from this repository (also by id).

We then take the existing rule and convert it into a scope.

```yaml
scope:
  create-tag:
    rule:
      if: |-
        assertion.job_workflow_ref == "abcxyz/pkg/.github/workflows/create-tag.yml@refs/heads/main" &&
        assertion.workflow_ref.startsWith("abcxyz/github-token-minter/.github/workflows/create-tag.yml") &&
        assertion.ref == 'refs/heads/main' &&
        assertion.event_name == 'workflow_dispatch'
    repositories:
      - 'github-token-minter'
    permissions:
      contents: 'write'
```

We would repeat this for any other rules contained in the file granting each rule its own scope.

This file should then be commited to the target repository as `minty.yaml` in the `.github` directory.

### Deploying the new configuration

Once the `minty.yaml` has been converted and checked in to the target repository we need to tell the `github-token-minter` service to read that file instead of the local configuration. To do this we remove the original file and redeploy the service.

## GitHub action changes

The `mint-token` action was also updated to do token revocation as part of the post cleanup process. The new `minty` action and its usage are outlined in the [README.md](../../README.md) at the top level of this repository. Migration to the new action should be done incrementally and should be done separately from the configuration updates.

For action workflows that requested permissions in the legacy configuration file, you need to update them to contain the `scope` that you define in the new configuration file.

An existing workflow job definition like:

```yaml
      - id: 'mint-github-token'
        uses: './.github/actions/mint-token'
        with:
          wif_provider: '${{ vars.WIF_PROVIDER }}'
          wif_service_account: '${{ vars.WIF_SERVICE_ACCOUNT }}'
          service_audience: '${{ env.INTEGRATION_SERVICE_AUDIENCE }}'
          service_url: '${{ env.INTEGRATION_SERVICE_URL }}'
          requested_permissions: '{"repositories":["github-token-minter"],"permissions":{"issues":"read"}}'
```

would become

```yaml
      - id: 'mint-github-token'
        uses: './.github/actions/mint-token'
        with:
          wif_provider: '${{ vars.WIF_PROVIDER }}'
          wif_service_account: '${{ vars.WIF_SERVICE_ACCOUNT }}'
          service_audience: '${{ env.INTEGRATION_SERVICE_AUDIENCE }}'
          service_url: '${{ env.INTEGRATION_SERVICE_URL }}'
          requested_permissions: '{"scope":"integ","repositories":["github-token-minter"],"permissions":{"issues":"read"}}'
```
