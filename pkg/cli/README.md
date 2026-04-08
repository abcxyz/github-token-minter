# CLI Package

This package implements the command-line interface for the `github-token-minter` (also known as `minty`).

## Purpose

The `cli` package provides the commands and flags for interacting with the `github-token-minter` system. It uses the `github.com/abcxyz/pkg/cli` library to structure the commands.

## Files

- **`root.go`**: Defines the root command `minty` and its subcommands: `server` and `tools`. It wires up the other commands.
- **`server.go`**: Implements the `server run` command, which starts the token minter server.
- **`mintycfg.go`**: Implements the `tools validate-cfg` command, which validates the configuration.
- **`minter.go`**: Implements the `tools mint` command, which exchanges an OIDC token for a GitHub token.
- **`private_key_import_cfg.go`**: Implements the `tools import-pk` command, which imports a GitHub private key into Google Cloud KMS.
