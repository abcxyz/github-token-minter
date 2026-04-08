# Config Package

This package defines the structures and utilities for loading and evaluating configuration files for `github-token-minter`.

## Purpose

The `config` package is responsible for:
- Defining the configuration schema (V1 and V2).
- Loading configuration files from local disk or remote sources (GitHub).
- Compiling and evaluating rules defined in Common Expression Language (CEL).
- Providing detailed traces of evaluation results.

## Files

- **`config.go`**: Defines core structures like `Config`, `Scope`, `Rule` and the evaluation logic using CEL.
- **`config_loader.go`**: Defines `ConfigFileLoader` interface and implementations for loading configurations from different sources (local files, in-repo files, cached, etc.).
- **`config_v1.go`**: Provides support for the legacy V1 configuration format and conversion to V2.
- **`cel_formatter.go`**: Implements formatting of CEL evaluation details into a human-readable trace.
- **`config_evaluator.go`**: Defines `ConfigEvaluator` which orchestrates loading and evaluating configs from multiple sources.
