# Minter Package

This package implements the `mint` tool, which is used to exchange an OIDC token for a GitHub token by calling the `github-token-minter` server.

## Purpose

The `minter` package provides the logic for the `tools mint` CLI command. It:
- Validates the provided OIDC token locally before sending it.
- Parses the token request.
- Sends a request to the `github-token-minter` server.
- Prints the resulting GitHub token.

## Files

- **`config.go`**: Defines the configuration for the minter command (Request, Token, MintyURL).
- **`runner.go`**: Implements the logic to validate the token and make the HTTP request to the server.
