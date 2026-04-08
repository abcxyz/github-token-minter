# Source Package

This package defines the abstraction for interacting with source control systems and provides a GitHub implementation.

## Purpose

The `source` package is used by the server to:
- Mint access tokens for specific repositories and permissions.
- Retrieve configuration files from repositories.
- Handle retries for API calls.

## Files

- **`source_system.go`**: Defines the `System` interface.
- **`github.go`**: Implements the `System` interface for GitHub, using GitHub Apps for authentication.
