// Copyright 2024 The Authors (see AUTHORS file)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The mintycfg package contains a CLI command that can be used to validate minty
// configuration files.
package mintycfg

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/cel-go/cel"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/github-token-minter/pkg/policy"
)

type singleFileConfigLoader struct {
	filePath string
}

// Load reads the contents of configuration files from the local file system.
func (l *singleFileConfigLoader) Load(ctx context.Context, org, repo string) (*config.Config, error) {
	data, err := os.ReadFile(l.filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading content from file: %w", err)
	}
	config, err := config.Read(data)
	if err != nil {
		return nil, fmt.Errorf("error converting raw config bytes into struct: %w", err)
	}
	return config, nil
}

func (l *singleFileConfigLoader) Source(org, repo string) string {
	return fmt.Sprintf("file://%s", l.filePath)
}

func (l *singleFileConfigLoader) SourceType() string {
	return "local"
}

func Run(ctx context.Context, cfg *Config) error {
	// create an environment to compile any cel expressions
	env, err := cel.NewEnv(
		cel.Variable(config.AssertionKey, cel.DynType),
		cel.Variable(config.IssuersKey, cel.DynType),
	)
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}

	var mintyConfig *config.Config
	if cfg.MintyFile != "" {
		loader := config.NewCompilingConfigLoader(env, &singleFileConfigLoader{filePath: cfg.MintyFile})
		var err error
		mintyConfig, err = loader.Load(ctx, "", "")
		if err != nil {
			fmt.Printf("\n\n-- Error --\n%v\n\n", err)
			return fmt.Errorf("configuration failed to compile")
		}

		// render the configuration information
		fmt.Printf("\n#################\n\n")
		fmt.Printf("\nConfiguration and all rules compiled successfully\n")
		fmt.Printf("Config:\n")
		fmt.Printf("- Version: %s\n", mintyConfig.Version)
		if mintyConfig.Rule != nil {
			fmt.Printf("- Rule.If: %s\n", mintyConfig.Rule.If)
		} else {
			fmt.Printf("- Rule.If: <nil>\n")
		}
		fmt.Printf("- Scopes: \n")
		for key, s := range mintyConfig.Scopes {
			fmt.Printf("  - %s:\n", key)
			if s.Rule != nil {
				fmt.Printf("    - Rule.If: %s\n", s.Rule.If)
			} else {
				fmt.Printf("    - Rule.If: <nil>\n")
			}
			fmt.Printf("    - Repositories: %v\n", s.Repositories)
			fmt.Printf("    - Permissions: %v\n", s.Permissions)
		}
		fmt.Printf("\n#################\n\n")
	}

	var policyEval *policy.Evaluator
	if cfg.PolicyPath != "" {
		var err error
		policyEval, err = policy.LoadPolicies(cfg.PolicyPath)
		if err != nil {
			return fmt.Errorf("policy loading failed: %w", err)
		}
		fmt.Printf("\nPolicy loaded successfully\n\n")
	}

	if mintyConfig != nil && policyEval != nil {
		input := map[string]any{
			"config": mintyConfig,
			"source": "local",
			"repo":   "test-repo",
			"org":    "test-org",
		}
		if cfg.Token != "" {
			var token map[string]any
			if err := json.Unmarshal([]byte(cfg.Token), &token); err != nil {
				return fmt.Errorf("error unmarshalling token content: %w", err)
			}
			input["token"] = token

			// Get org/repo from token if available
			if org, ok := token["repository_owner"].(string); ok {
				input["org"] = org
			}
			if repo, ok := token["repository"].(string); ok {
				input["repo"] = repo
			}
		}

		denies, err := policyEval.Evaluate(ctx, input)
		if err != nil {
			return fmt.Errorf("policy evaluation failed: %w", err)
		}
		if len(denies) > 0 {
			fmt.Printf("\nPolicy violations found:\n")
			for _, d := range denies {
				fmt.Printf("- %s\n", d)
			}
			fmt.Printf("\nPolicy validation failed\n\n")
		} else {
			fmt.Printf("\nPolicy validation passed\n\n")
		}
	}

	// if a scope and a token were provided, run evaluation against them to
	// determine if there is a scope match and then output the scope contents
	if cfg.Scope != "" && cfg.Token != "" && mintyConfig != nil {
		var token map[string]any
		if err := json.Unmarshal([]byte(cfg.Token), &token); err != nil {
			return fmt.Errorf("error unmarshalling token content: %w", err)
		}
		// Format the token data for printing
		json, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal token: %w", err)
		}
		fmt.Printf("\n#################\n\n")
		fmt.Printf("Token:\n")
		fmt.Println(string(json))
		fmt.Printf("\n#################\n\n")

		fmt.Printf("Evaluating token against scope: %s\n", cfg.Scope)
		scope, decision, err := mintyConfig.Eval(cfg.Scope, token)
		if err != nil || scope == nil || !decision.Allowed {
			fmt.Printf("\nEval decision: \n%v\n\n", decision.Details)
			fmt.Printf("Requested scope was not found or did not match the criteria based on the provided token: %v\n", cfg.Scope)
		} else {
			fmt.Printf("Found match for scope: %s\n", cfg.Scope)
			fmt.Printf("  - Permissions: %v\n", scope.Permissions)
			fmt.Printf("  - Repositories: %v\n", scope.Repositories)
		}
		fmt.Printf("\n#################\n\n")
	}

	fmt.Println("Configuration parsed and loaded successfully")

	return nil
}
