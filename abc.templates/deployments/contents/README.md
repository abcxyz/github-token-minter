# Deployment Configurations

### TLDR
1. Create a `<repo-name>.yaml` file for each repository in `REPLACE_SUBDIRECTORY`.
1. Customize the configuration.
1. Build and deploy a new image with new configurations.

### Configure Repository Access

Each repository that needs to mint a token must be configured with an allowed set of permissions. Any request from a repository that is not configured will default to denying all access.

Each configuration file can have 1 or more rules that it can match against and it will evaluate them in order, top down, until it finds a matching condition.

The repository configuration file looks like below and is made up of three primary sections:

```yaml
# abcxyz/github-token-minter.yaml
-
  if: 'assertion.workflow_ref.startsWith("abcxyz/github-token-minter/.github/workflows/ci.yml")'
  repositories:
    - 'github-token-minter'
  permissions:
    issues: 'read'
```

The `if` clause uses the [Google Common Expression Language](https://github.com/google/cel-spec) to match an inbound OIDC token against a series of rules. Any attributes from the assertion object are available to match against and you can make this expression as simple or complicated as required.

The object mirrors what is available in an [OIDC token for a GitHub Workflow](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#configuring-the-oidc-trust-with-the-cloud).

The `repositories` and `permissions` attributes mirror the schema defined for [requesting a GitHub app installation access token](https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app).

* Repositories is an array of strings representing the name of the repository. Since the GitHub app only services a single organization per installation you do not need to specify the organization name as part of the repository name. E.g. `github-token-minter` instead of `abcxyz/github-token-minter`. The repository attribute supports a prefix wildcard match so you can select multiple repositories at once. A single `*` would capture all repositories for the organization but something like `github-*` would only capture repositories that started with `github-`.

* Permissions is a map of permission name to access level. For example, to generate a token that can read issues you would specify `"issues": "read"`.
