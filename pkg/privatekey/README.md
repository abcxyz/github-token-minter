# Privatekey Package

This package implements the logic for importing GitHub private keys into Google Cloud KMS.

## Purpose

The `privatekey` package provides the logic for the `tools import-pk` CLI command. It:
- Interacts with Google Cloud KMS to ensure key rings and keys exist.
- Creates import jobs.
- Wraps the private key securely and imports it into Cloud KMS.

## Files

- **`config.go`**: Defines the configuration for the import command (ProjectID, Location, KeyRing, Key, PrivateKey, ImportJobPrefix).
- **`kms.go`**: Implements `KeyServer` which handles the interaction with Cloud KMS API, including wrapping and importing the key.
