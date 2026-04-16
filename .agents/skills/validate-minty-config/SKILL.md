---
name: validate-minty-config
description: Validates Minty configuration files using the `tools validate` command.
---
# Validate Minty Configuration

This skill provides instructions for validating Minty configuration files using the CLI.

## Usage

To validate a configuration file, run:

```bash
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools validate --minty-file <path/to/config.yaml>
```

### Optional Arguments


- `--scope <scope>`: Validate against a specific scope.
- `--token <token_json>`: Validate using a specific token (JSON string).
- `--policy <path>`: Path to a policy file or directory to validate.

> [!NOTE]
> If any required arguments (like the config file path) or optional arguments (like scope or token) are not provided or known from context, **ask the user for them** before running the command.

### Policy Validation

The command can also validate Rego policies.

**Syntax Check Only:**
```bash
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools validate --policy <path/to/policy.rego>
```
Output on success: `policy compiled`.

**Combined Validation:**
```bash
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools validate \
  --minty-file <path/to/config.yaml> \
  --policy <path/to/policy.rego>
```
You can also provide `--token` to simulate the token input for policy evaluation.

### Using Log Entries

If the user provides a server log entry (JSON), extract the following fields:

- **Token**: Use the content of `jsonPayload.claims` as the value for `--token`.
- **Scope**: Use the content of `jsonPayload.request.scope` as the value for `--scope`.

**Example Extraction:**

Given a log entry:
```json
{
  "jsonPayload": {
    "request": { "scope": "my-scope" },
    "claims": { "iss": "..." }
  }
}
```

Run:
```bash
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools validate \
  --minty-file <config> \
  --scope "my-scope" \
  --token '{"iss": "..."}'
```

### Fetching Config from GitHub

If a log entry is provided, you can also fetch the configuration file directly from GitHub using the `repository` and `ref` claims.

1.  **Extract Repo and Ref**:
    -   `repository`: from `jsonPayload.claims.repository` (e.g., `owner/repo`).
    -   `ref`: from `jsonPayload.claims.ref` (e.g., `refs/heads/main` or `refs/tags/v1`).

2.  **Download Config**:
    Use `gh api` to download the file to a temporary location. Valid paths are typically `.github/minty.yaml` or `.github/minty.yml`.

    ```bash
    # Example for ref 'refs/heads/main'
    gh api repos/<owner>/<repo>/contents/.github/minty.yaml?ref=<ref> \
      -H "Accept: application/vnd.github.raw" > minty.yaml
    ```

3.  **Run Validation**:
    Use the downloaded `minty.yaml` as the `--minty-file`.

### Example

```bash
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools validate --minty-file config.yaml --scope "my-scope" --token '{"iss":"..."}'
```

## Output Interpretation

- **Success**: The command will output "Configuration parsed and loaded successfully".
- **Failure**: The command will output a hierarchical evaluation tree.
    - `[x]` indicates a failing condition.
    - `[+]` indicates a passing condition.
    - Look for the specific leaf node where the expected value (Lit) differs from the actual value (Select) to advise the user on what claim is missing or incorrect.

## Debugging

When a validation fails, the tool outputs a decision tree. Use this to pinpoint exactly which claim failed.

Example Failure Output:
```text
Eval decision: 
[x] AND -> false
├── [+] AND -> true
│   ├── [+] EQUALS -> true
│   │   ├── [v] Select 'assertion.job_workflow_ref' -> ...
...
└── [x] AND -> false
    ├── [x] EQUALS -> false
    │   ├── [v] Select 'assertion.ref' -> refs/heads/wrong-branch
    │   └── [v] Lit 'refs/heads/main' -> refs/heads/main
```

In this example, `assertion.ref` was `refs/heads/wrong-branch` but the policy required `refs/heads/main`. Advise the user to check their token generation or branch name.
