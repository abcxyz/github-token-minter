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

func Run(ctx context.Context, cfg *Config) error {
	// create an environment to compile any cel expressions
	env, err := cel.NewEnv(cel.Variable("assertion", cel.DynType))
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}
	// load the requested configuration file and attempte to compile all CEL expressions
	loader := config.NewCompilingConfigLoader(env, &singleFileConfigLoader{filePath: cfg.MintyFile})
	config, err := loader.Load(ctx, "", "")
	if err != nil {
		fmt.Printf("\nConfiguration failed to compile\n")
		fmt.Printf("-- Error --\n%v\n", err)
		return nil
	}

	// render the configuration information
	fmt.Printf("\n#################\n\n")
	fmt.Printf("\nConfiguration and all rules compiled successfully\n")
	fmt.Printf("Config:\n")
	fmt.Printf("- Version: %s\n", config.Version)
	fmt.Printf("- Rule.If: %s\n", config.Rule.If)
	fmt.Printf("- Scopes: \n")
	for key, s := range config.Scopes {
		fmt.Printf("  - %s:\n", key)
		fmt.Printf("    - Rule.If: %s\n", s.Rule.If)
		fmt.Printf("    - Repositories: %v\n", s.Repositories)
		fmt.Printf("    - Permissions: %v\n", s.Permissions)
	}
	fmt.Printf("\n#################\n\n")

	// if a scope and a token were provided, run evaluation against them to
	// determine if there is a scope match and then output the scope contents
	if cfg.Scope != "" && cfg.Token != "" {
		var token map[string]string
		if err := json.Unmarshal([]byte(cfg.Token), &token); err != nil {
			return fmt.Errorf("error unmarshalling token content: %w", err)
		}

		scope, err := config.Eval(cfg.Scope, token)
		if err != nil {
			return fmt.Errorf("error evaluating scope: %q - %w", cfg.Scope, err)
		}
		fmt.Printf("Evaluated token against scope: %s\n", cfg.Scope)
		fmt.Printf("Found scope: %v\n", cfg.Scope)
		fmt.Printf("  - Permissions: %v\n", scope.Permissions)
		fmt.Printf("  - Repositories: %v\n", scope.Repositories)
		fmt.Printf("\n#################\n\n")
	}

	fmt.Println("Configuration parsed and loaded successfully")

	return nil
}
