# Version Package

This package defines version information for the `github-token-minter` project.

## Purpose

The `version` package provides variables that store the application name, version, git commit SHA, and OS/Architecture. These are used in logging and CLI output.

## Files

- **`version.go`**: Defines the version variables and initializes them, trying to read from build info if available.
