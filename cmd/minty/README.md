# Minty Command

This directory contains the main entry point for the `minty` CLI tool.

## Purpose

The `cmd/minty` package provides the main function that runs the `minty` CLI. It sets up context with signal handling and logging, and delegates execution to the `pkg/cli` package.

## Files

- **`main.go`**: The entry point file containing `main` and `realMain` functions.
