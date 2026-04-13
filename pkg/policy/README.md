# Policy Package

This package implements the Rego policy evaluation engine for Minty. It uses the OPA (Open Policy Agent) Go SDK to evaluate policies against token requests.

## Usage

```go
import "github.com/abcxyz/github-token-minter/pkg/policy"

// Load policies from a directory
evaluator, err := policy.LoadPolicies("/path/to/policy/dir")
if err != nil {
    // handle error
}

// Evaluate a request
input := map[string]any{
    "config": ...,
    "source": "local",
    "repo": "my-repo",
    "org": "my-org",
    "token": claims,
}

denies, err := evaluator.Evaluate(ctx, input)
if err != nil {
    // handle error
}

if len(denies) > 0 {
    // request denied
    fmt.Println("Denied:", denies)
}
```

## Rego Package Convention

Policies must use the package `minty.policy` and define a rule named `deny` that evaluates to a set or list of strings.

```rego
package minty.policy

deny contains msg if {
    # conditions
    msg := "denial message"
}
```
