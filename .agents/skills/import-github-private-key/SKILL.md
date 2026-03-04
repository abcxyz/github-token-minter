---
name: import-github-private-key
description: Imports a GitHub private key into Google Cloud KMS.
---
# Import GitHub Private Key

This skill provides instructions for importing a GitHub private key into Google Cloud KMS using the Minty CLI.

## Usage

To import a private key, run:

```bash
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools import-pk \
  --project-id <project_id> \
  --location <location> \
  --key-ring <key_ring> \
  --key <key_name> \
  --private-key <path/to/private-key.pem>
```

### Arguments

- `--project-id`: The Google Cloud Project ID.
- `--location`: The Cloud KMS location (default: `global`).
- `--key-ring`: The name of the key ring.
- `--key`: The name of the key.
- `--private-key`: Path to the private key file (PEM format). Use `-` to read from stdin.
- `--import-job-prefix`: Prefix for the import job (default: `app-signing-key`).

> [!NOTE]
> If these arguments are not provided or known from context (e.g., Project ID, Key Ring), **ask the user for them**.

## Example

```bash
go run github.com/abcxyz/github-token-minter/cmd/minty@main tools import-pk \
  --project-id my-project \
  --location global \
  --key-ring my-key-ring \
  --key my-app-key \
  --private-key ./private-key.pem
```
