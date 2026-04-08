# Mintycfg Package

This package implements the `validate-cfg` tool, which is used to validate `github-token-minter` configuration files.

## Purpose

The `mintycfg` package provides the logic for the `tools validate-cfg` CLI command. It:
- Loads a specific configuration file.
- Compiles all CEL expressions to ensure they are valid.
- Prints the structure of the configuration.
- Optionally evaluates a token against a scope to test the configuration.

## Files

- **`config.go`**: Defines the configuration for the validate-cfg command (MintyFile, Scope, Token).
- **`runner.go`**: Implements the logic to load, compile, and optionally evaluate the configuration.
