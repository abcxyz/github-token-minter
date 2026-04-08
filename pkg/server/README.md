# Server Package

This package implements the HTTP server for `github-token-minter`.

## Purpose

The `server` package provides the core functionality of the service:
- Accepts requests with OIDC tokens.
- Validates tokens and claims.
- Evaluates access policies based on configuration.
- Mints GitHub access tokens with requested permissions.
- Exposes `/token` and `/version` endpoints.

## Subdirectories

- **[`source`](file:///Users/bradegler/opt/abcxyz/github-token-minter/pkg/server/source)**: Defines the abstraction for interacting with source control systems (GitHub).

## Files

- **`token_minter.go`**: The core server implementation, handling requests and orchestrating validation and minting.
- **`config.go`**: Defines the server configuration, including flags and environment variables.
- **`claims.go`**: Handles parsing and validation of OIDC claims.
- **`jwk_resolver.go`**: Resolves JSON Web Keys for verifying OIDC tokens.
- **`permissions.go`**: Validates requested permissions against allowed permissions.
- **`runner.go`**: Sets up and runs the HTTP server.
