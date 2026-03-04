---
name: mint-github-token
description: Exchange an OIDC token for a GitHub token using Minty.
---
# Mint GitHub Token

This skill provides instructions for exchanging an OIDC token (from Google or GitHub) for a GitHub App installation token using the Minty CLI.

## Prerequisites

- `gcloud` CLI (for Google ID tokens) or `gh` CLI (for GitHub ID tokens, if applicable).
- A running Minty server (or access to one).

## Usage

To mint a token, run:

```bash
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools mint \
  --mintyURL <minty_server_url> \
  --token <oidc_token> \
  --request <request_json>
```

### Arguments

- `--mintyURL`: The URL of the Minty server (e.g., `https://minty.example.com`).
- `--token`: The OIDC token to exchange.
- `--request`: A JSON string containing the token request details (e.g., repositories and permissions).

> [!NOTE]
> If these arguments are not provided or known from context (e.g., the Minty URL), **ask the user for them**.

### Generating ID Tokens

#### Google Service Account (gcloud)

To use a Google Service Account (impersonation):

```bash
# Get the ID token
export OIDC_TOKEN=$(gcloud auth print-identity-token --impersonate-service-account <sa-email> --audiences <minty-audience>)

# Run minter
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools mint \
  --mintyURL <url> \
  --token $OIDC_TOKEN \
  --request '{"repositories": ["my-repo"], "permissions": {"contents": "read"}}'
```

#### GitHub CLI (gh)

To use your GitHub identity, you must obtain an **OIDC token** (JWT), not a standard opaque personal access token.
- **Actions/Codespaces**: `gh` can generate OIDC tokens in these environments.
- **Local Development**: `gh auth token` typically returns an opaque token (e.g., `ghp_...`), which **will not work** if Minty requires OIDC.
    - **Recommendation**: Use Google Service Account impersonation for local user flows if configured.
    - If you *must* use GitHub locally, ensuring `gh` returns a JWT requires specific configuration (e.g., enterprise managed users or specific auth flows).

## Example

```bash
# 1. Get Token
export TOKEN=$(gcloud auth print-identity-token \
  --impersonate-service-account minty-client@my-project.iam.gserviceaccount.com \
  --audiences "https://minty.abcxyz.dev")

# 2. Request GitHub Token
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools mint \
  --mintyURL "https://minty-service-url" \
  --token "$TOKEN" \
  --request '{"repositories": ["github-token-minter"], "permissions": {"issues": "write"}}'
```
