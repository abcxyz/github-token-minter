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

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
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

func Run(ctx context.Context, cfg *Config) error {
	// create an environment to compile any cel expressions
	env, err := cel.NewEnv(
		cel.Variable(config.AssertionKey, cel.DynType),
		cel.Variable(config.IssuersKey, cel.DynType),
	)
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}
	// load the requested configuration file and attempte to compile all CEL expressions
	loader := config.NewCompilingConfigLoader(env, &singleFileConfigLoader{filePath: cfg.MintyFile})
	mintyConfig, err := loader.Load(ctx, "", "")
	if err != nil {
		fmt.Printf("\n\n-- Error --\n%v\n\n", err)
		return fmt.Errorf("configuration failed to compile")
	}

	// render the configuration information
	fmt.Printf("\n#################\n\n")
	fmt.Printf("\nConfiguration and all rules compiled successfully\n")
	fmt.Printf("Config:\n")
	fmt.Printf("- Version: %s\n", mintyConfig.Version)
	fmt.Printf("- Rule.If: %s\n", mintyConfig.Rule.If)
	fmt.Printf("- Scopes: \n")
	for key, s := range mintyConfig.Scopes {
		fmt.Printf("  - %s:\n", key)
		fmt.Printf("    - Rule.If: %s\n", s.Rule.If)
		fmt.Printf("    - Repositories: %v\n", s.Repositories)
		fmt.Printf("    - Permissions: %v\n", s.Permissions)
	}
	fmt.Printf("\n#################\n\n")

	// if a scope and a token were provided, run evaluation against them to
	// determine if there is a scope match and then output the scope contents
	if cfg.Scope != "" && cfg.Token != "" {
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
		scope, err := mintyConfig.Eval(cfg.Scope, token)
		if err != nil || scope == nil {
			// Check global rule first
			if err := evalToken("global", mintyConfig.Rule.If, env, token); err != nil {
				return err
			}
			// Check for existence of named scope
			val, ok := mintyConfig.Scopes[cfg.Scope]
			if !ok {
				fmt.Printf("named scope not found: %q", cfg.Scope)
				return nil
			}
			// Check scope rule next
			if err := evalToken("scope", val.Rule.If, env, token); err != nil {
				return err
			}
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

func evalToken(ruleType, ruleIf string, env *cel.Env, token map[string]any) error {
	prg, err := compileExpression(env, ruleIf)
	if err != nil {
		return fmt.Errorf("failed to compile %s CEL expression: %w", ruleType, err)
	}
	out, details, err := prg.Eval(map[string]any{
		config.AssertionKey: token,
		config.IssuersKey:   config.IssuersMap,
	})
	fmt.Printf("%s CEL Details - State:\n%v\n", ruleType, details.State())
	fmt.Printf("%s CEL Result: %v\n\n", ruleType, out)
	if !matched(out) {
		fmt.Printf("failed to match %s CEL expression", ruleType)
		fmt.Printf("rule: %q", ruleIf)
	}
	if err != nil {
		return fmt.Errorf("failed %s CEL expression: %w", ruleType, err)
	}
	return nil
}

func compileExpression(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
	}

	prg, err := env.Program(ast, cel.EvalOptions(cel.OptExhaustiveEval))
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return prg, nil
}

func matched(out ref.Val) bool {
	if v, ok := (out.Value()).(bool); v && ok {
		return true
	}
	return false
}
