# Mintycfg Package

This package implements the `validate` tool, which is used to validate `github-token-minter` configuration files and policies.

## Purpose

The `mintycfg` package provides the logic for the `tools validate` CLI command. It:
- Loads a specific configuration file.
- Compiles all CEL expressions to ensure they are valid.
- Prints the structure of the configuration.
- Optionally evaluates a token against a scope to test the configuration.
- Validates Rego policies (syntax check and evaluation against config).

## Files

- **`config.go`**: Defines the configuration for the validate command (MintyFile, Scope, Token, PolicyPath).
- **`runner.go`**: Implements the logic to load, compile, and optionally evaluate the configuration and policies.
