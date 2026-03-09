---
name: generate-minty-config
description: Generates a Minty configuration file to allow automation accounts (Service Accounts or GitHub Actions) to access the repository.
---
# Generate Minty Configuration

This skill helps you generate a `.github/minty.yaml` configuration file to grant access to restricted tokens.

## Context

Minty controls who can mint tokens for a repository.
For **Enterprise Read-Only** access, we want to allow specific Service Accounts or GitHub Actions to have `contents: read` access.

## Capabilities

1.  **Identify Requester**: Ask the user for the Service Account email or GitHub Action details.
2.  **Fetch IDs**: If it's a GitHub Action, use `gh api` to find the `repository_id` and `repository_owner_id` of the *source* repository (the one *requesting* access).
3.  **Generate YAML**: Create a valid Minty config.
4.  **Validate**: Run `minty tools validate-cfg`.

## Step-by-Step Instructions

### 1. Identify Requester

Ask the user:
> "Is the requester a Google Cloud Service Account or a GitHub Action?"

**If Service Account**:
-   Ask for the **Service Account Email**.

**If GitHub Action**:
-   Ask for:
    -   **Source Repository** (`owner/repo` format).
    -   **Workflow Name** (e.g., `ci.yml` or "CI Pipeline").
    -   **Ref** (e.g., `refs/heads/main`).

### 2. Fetch IDs (GitHub Action Only)

If the requester is a GitHub Action, you **MUST** look up the IDs to ensure stable identification.

Use `gh` to get the IDs:
```bash
# Get Repo ID
gh api repos/<owner>/<repo> --jq .id

# Get Owner ID
gh api users/<owner> --jq .id
```

### 3. Generate Configuration

Create or update `.github/minty.yaml`.

**Template for Service Account**:
```yaml
version: 'minty.abcxyz.dev/v1'
rule:
  if: 'assertion.email == "<EMAIL>"'
scope:
  read-only:
    permissions:
      contents: read
      metadata: read
```

**Template for GitHub Action**:
```yaml
version: 'minty.abcxyz.dev/v1'
rule:
  if: 'assertion.repository_id == "<REPO_ID>" && assertion.repository_owner_id == "<OWNER_ID>" && assertion.workflow == "<WORKFLOW>" && assertion.ref == "<REF>"'
scope:
  read-only:
    permissions:
      contents: read
      metadata: read
```

> [!NOTE]
> Ensure IDs are treated as strings in the CEL expression (wrapped in quotes) if the server expects strings, even if `gh api` returns numbers. The server compares them as strings.

### 4. Validate Configuration

Run the validation tool to ensure the config is correct.

```bash
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools validate-cfg --minty-file .github/minty.yaml
```

If you have specific values to test (conflicting with the rule), you may need to pass `--token '{"...": "..."}'` to simulate a match, but basic validation checks structure.
