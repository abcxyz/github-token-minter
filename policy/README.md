# Minty Policies

This directory contains Rego policies used by Minty to enforce security guardrails at deployment time.

## Usage

Policies are loaded from this directory by default if it exists. The directory can be configured using the `MINTY_POLICY_DIR` environment variable or `--policy-dir` flag.

All `.rego` files in this directory are loaded and evaluated. Policies must define rules in the `data.minty.policy` package and add denial messages to the `deny` set.

## Included Policies

### [read_only.rego](./read_only.rego)

Enforces that all requested permissions are read-only. This is useful for deployments where Minty should never grant write access, regardless of what is configured in repository `minty.yaml` files.

### [centralized_cross_repo.rego](./centralized_cross_repo.rego)

Enforces that cross-repository token requests (where a repo requests access to another repo) are only allowed if the configuration comes from a "central" source (e.g., a central admin repository). This prevents individual repositories from granting themselves access to other repositories without central approval.

### [fail_safe.rego](./fail_safe.rego)

Provides a template for enterprise, organization, and repository ID allow-listing. This acts as a fail-safe to ensure that tokens are only minted for authorized entities, even if a request somehow bypasses other protections.

**IMPORTANT**: You must replace the placeholder values (`YOUR_ENTERPRISE_ID`, `YOUR_ORG_ID`, `YOUR_REPO_ID`) with your actual IDs before enabling this policy!

## Policy Input Schema

The policy evaluator passes an object to Rego as `input` with the following structure:

```json
{
  "config": {
    "version": "minty.abcxyz.dev/v2",
    "rule": { ... },
    "scopes": { ... }
  },
  "source": "local|repo|central",
  "repo": "target-repo-name",
  "org": "target-org-name",
  "token": {
    "enterprise_id": "...",
    "repository_owner_id": "...",
    "repository_id": "...",
    ... (other OIDC claims)
  }
}
```
