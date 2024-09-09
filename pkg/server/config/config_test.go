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

package config

import (
	"testing"

	"github.com/google/cel-go/cel"

	"github.com/abcxyz/pkg/testutil"
)

func TestCompileExpression(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		expr      string
		expErr    bool
		expErrMsg string
	}{
		{
			name:   "success",
			expr:   "assertion.workflow == 'Test' && assertion.actor == 'test'",
			expErr: false,
		},
		{
			name:      "failure to parse, no assertion",
			expr:      "actor == 'test'",
			expErr:    true,
			expErrMsg: "failed to compile CEL expression: ERROR: <input>:1:1: undeclared reference to 'actor' (in container '')\n | actor == 'test'\n | ^",
		},
	}
	for _, tc := range cases {
		tc := tc

		env, _ := cel.NewEnv(cel.Variable(assertionKey, cel.DynType))
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pgm, err := compileExpression(env, tc.expr)
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}
			if !tc.expErr && pgm == nil {
				t.Errorf("program nil without error")
			}
		})
	}
}

func TestRulesetCompile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		ruleset   Rule
		expErr    bool
		expErrMsg string
	}{
		{
			name:    "success",
			ruleset: Rule{If: "assertion.workflow == 'Test' && assertion.actor == 'test'"},
			expErr:  false,
		},
		{
			name:      "failure to parse, no assertion",
			ruleset:   Rule{If: "actor == 'test'"},
			expErr:    true,
			expErrMsg: "failed to compile CEL expression: ERROR: <input>:1:1: undeclared reference to 'actor' (in container '')\n | actor == 'test'\n | ^",
		},
	}
	for _, tc := range cases {
		tc := tc

		env, _ := cel.NewEnv(cel.Variable(assertionKey, cel.DynType))
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.ruleset.compile(env)
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}
			if !tc.expErr && tc.ruleset.Program == nil {
				t.Errorf("program nil without error")
			}
		})
	}
}

func TestScopeCompile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		ruleset   Scope
		expErr    bool
		expErrMsg string
	}{
		{
			name:    "success",
			ruleset: Scope{Rule: Rule{If: "assertion.workflow == 'Test' && assertion.actor == 'test'"}},
			expErr:  false,
		},
		{
			name:      "failure to parse, no assertion",
			ruleset:   Scope{Rule: Rule{If: "actor == 'test'"}},
			expErr:    true,
			expErrMsg: "failed to compile CEL expression: ERROR: <input>:1:1: undeclared reference to 'actor' (in container '')\n | actor == 'test'\n | ^",
		},
	}
	for _, tc := range cases {
		tc := tc

		env, _ := cel.NewEnv(cel.Variable(assertionKey, cel.DynType))
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.ruleset.compile(env)
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}
			if !tc.expErr && tc.ruleset.Rule.Program == nil {
				t.Errorf("program nil without error")
			}
		})
	}
}

func TestConfigCompile(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		config    Config
		expErr    bool
		expErrMsg string
	}{
		{
			name: "success",
			config: Config{
				Rule: Rule{If: "assertion.workflow == 'Test' && assertion.actor == 'test'"},
				Scopes: map[string]*Scope{
					"test": {
						Rule: Rule{If: "assertion.workflow == 'Test' && assertion.actor == 'test'"},
					},
				},
			},
			expErr: false,
		},
		{
			name: "failure to parse, no assertion",
			config: Config{
				Rule: Rule{If: "actor == 'test'"},
				Scopes: map[string]*Scope{
					"test": {
						Rule: Rule{If: "assertion.actor == 'test'"},
					},
				},
			},
			expErr:    true,
			expErrMsg: "failed to compile CEL expression: ERROR: <input>:1:1: undeclared reference to 'actor' (in container '')\n | actor == 'test'\n | ^",
		},
	}
	for _, tc := range cases {
		tc := tc

		env, _ := cel.NewEnv(cel.Variable(assertionKey, cel.DynType))
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := tc.config.compile(env)
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}
			if !tc.expErr && tc.config.Rule.Program == nil {
				t.Errorf("policy program nil without error")
			}
			if !tc.expErr && tc.config.Scopes["test"].Rule.Program == nil {
				t.Errorf("scope program nil without error")
			}
		})
	}
}