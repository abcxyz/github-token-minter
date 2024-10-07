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

var issuersMap = map[string]string{
	"github": GitHubIssuer,
	"google": GoogleIssuer,
}

// Rule is a struct that contains the string representation
// of a CEL expresssion along with the compiled CEL Program.
type Rule struct {
	If      string      `yaml:"if" json:"if"`
	Program cel.Program `yaml:"-" json:"-"`
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
	prg, err := compileExpression(env, r.If)
	if err != nil {
		return fmt.Errorf("failed to compile ruleset: %w", err)
	}
	r.Program = prg
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

func compileExpression(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return prg, nil
}

func (r *Rule) eval(token interface{}) (bool, error) {
	if r == nil {
		return true, nil
	}
	out, _, err := r.Program.Eval(map[string]any{
		AssertionKey: token,
		IssuersKey:   issuersMap,
	})
	if err != nil {
		return false, fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	if v, ok := (out.Value()).(bool); v && ok {
		return true, nil
	}
	return false, nil
}

func (c *Config) Eval(scope string, token interface{}) (*Scope, error) {
	ok, err := c.Rule.eval(token)
	if err != nil {
		return nil, fmt.Errorf("global rule evaluation failed: %w", err)
	}
	if !ok {
		return nil, nil
	}

	if c.Version == configVersionV1 {
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
			ok, err = val.Rule.eval(token)
			if err != nil {
				return nil, fmt.Errorf("scope rule evaluation failed: %w", err)
			}
			if ok {
				return val, nil
			}
		}
		return nil, nil
	}

	val, ok := c.Scopes[scope]
	if ok {
		ok, err = val.Rule.eval(token)
		if err != nil {
			return nil, fmt.Errorf("scope rule evaluation failed: %w", err)
		}
		if ok {
			return val, nil
		}
	}
	return nil, nil
}
