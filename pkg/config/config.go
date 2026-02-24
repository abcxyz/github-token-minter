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

// package config defines structs and utilities for reading configuration
// file data into memory from various sources
package config

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/cel-go/cel"
)

const (
	configVersionV1 = "minty.abcxyz.dev/v1"
	configVersionV2 = "minty.abcxyz.dev/v2"
)

const (
	GitHubIssuer = "https://token.actions.githubusercontent.com"
	GoogleIssuer = "https://accounts.google.com"
)

var IssuersMap = map[string]string{
	"github": GitHubIssuer,
	"google": GoogleIssuer,
}

// Rule is a struct that contains the string representation
// of a CEL expresssion along with the compiled CEL Program.
type Rule struct {
	If      string      `yaml:"if" json:"if"`
	Program cel.Program `yaml:"-" json:"-"`
	Ast     *cel.Ast    `yaml:"-" json:"-"`
}

// PolicyDecision contains the result of a policy evaluation
// including whether it was allowed and the reason for the decision.
type PolicyDecision struct {
	Allowed bool
	Reason  string
	Details string
}

// Scope is a struct that contains a series of permissions that
// are associated with a Rule.
type Scope struct {
	Permissions  map[string]string `yaml:"permissions" json:"permissions"`
	Repositories []string          `yaml:"repositories" json:"repositories"`
	Rule         *Rule             `yaml:"rule" json:"rule"`
}

// Config is a struct that contains a top level rule that applies
// to all requests and a map of Scopes that can be requested. The
// map is keyed by a string name.
type Config struct {
	Version string            `yaml:"version" json:"version"`
	Rule    *Rule             `yaml:"rule" json:"rule"`
	Scopes  map[string]*Scope `yaml:"scope" json:"scope"`
}

type ConfigReader interface {
	Read(ctx context.Context, org, repo string) (*Config, error)
}

func (r *Rule) compile(env *cel.Env) error {
	if r == nil {
		return nil
	}
	prg, ast, err := compileExpression(env, r.If)
	if err != nil {
		return fmt.Errorf("failed to compile ruleset: %w", err)
	}
	r.Program = prg
	r.Ast = ast
	return nil
}

func (s *Scope) compile(env *cel.Env) error {
	return s.Rule.compile(env)
}

func (c *Config) compile(env *cel.Env) error {
	if err := c.Rule.compile(env); err != nil {
		return fmt.Errorf("error compiling configuration ruleset: %w", err)
	}
	for name, s := range c.Scopes {
		if err := s.compile(env); err != nil {
			return fmt.Errorf("error compiling configuration for scope [%s]: %w", name, err)
		}
	}
	return nil
}

func compileExpression(env *cel.Env, expr string) (cel.Program, *cel.Ast, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, nil, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
	}

	prg, err := env.Program(ast, cel.EvalOptions(cel.OptExhaustiveEval, cel.OptTrackState))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return prg, ast, nil
}

func (r *Rule) eval(token interface{}) (*PolicyDecision, error) {
	if r == nil {
		return &PolicyDecision{Allowed: true, Reason: "no rule defined, allowed by default"}, nil
	}
	out, details, err := r.Program.Eval(map[string]any{
		AssertionKey: token,
		IssuersKey:   IssuersMap,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	if v, ok := (out.Value()).(bool); v && ok {
		return &PolicyDecision{Allowed: true, Reason: fmt.Sprintf("rule matched: %s", r.If), Details: formatEvalDetails(r.Ast, details)}, nil
	}
	return &PolicyDecision{Allowed: false, Details: formatEvalDetails(r.Ast, details), Reason: fmt.Sprintf("rule failed: %s", r.If)}, nil
}

func (c *Config) Eval(scope string, token interface{}) (*Scope, *PolicyDecision, error) {
	// First check the global rule for this configuration
	decision, err := c.Rule.eval(token)
	if err != nil {
		return nil, nil, fmt.Errorf("global rule evaluation failed: %w", err)
	}
	if !decision.Allowed {
		return nil, decision, nil
	}

	if c.Version == configVersionV1 {
		return c.evalV1(token)
	}
	return c.evalV2(scope, token)
}

func (c *Config) evalV1(token interface{}) (*Scope, *PolicyDecision, error) {
	// Version 1 didn't have the concept of a "scope" and mapping based on
	// name. In situations where we are processing this old style configuration
	// we just walk through the map and look for a match. Matches were ordered
	// top to bottom and are inserted into the scopes map keyed as "default_xxxxxxxx"
	// to help maintain that ordering.
	keys := make([]string, 0, len(c.Scopes))
	for k := range c.Scopes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		val := c.Scopes[k]
		decision, err := val.Rule.eval(token)
		if err != nil {
			return nil, nil, fmt.Errorf("scope rule evaluation failed: %w", err)
		}
		if decision.Allowed {
			return val, decision, nil
		}
	}
	return nil, &PolicyDecision{Allowed: false, Reason: "no matching scope found in v1 config"}, nil
}

func (c *Config) evalV2(scope string, token interface{}) (*Scope, *PolicyDecision, error) {
	val, ok := c.Scopes[scope]
	if !ok {
		return nil, &PolicyDecision{Allowed: false, Reason: fmt.Sprintf("scope %q not found in config", scope)}, nil
	}

	decision, err := val.Rule.eval(token)
	if err != nil {
		return nil, nil, fmt.Errorf("scope rule evaluation failed: %w", err)
	}
	if decision.Allowed {
		return val, decision, nil
	}
	return nil, decision, nil
}
