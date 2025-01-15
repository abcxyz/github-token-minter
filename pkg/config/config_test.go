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
	"github.com/google/go-cmp/cmp"

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

		env, _ := cel.NewEnv(cel.Variable(AssertionKey, cel.DynType))
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

		env, _ := cel.NewEnv(cel.Variable(AssertionKey, cel.DynType))
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
			ruleset: Scope{Rule: &Rule{If: "assertion.workflow == 'Test' && assertion.actor == 'test'"}},
			expErr:  false,
		},
		{
			name:      "failure to parse, no assertion",
			ruleset:   Scope{Rule: &Rule{If: "actor == 'test'"}},
			expErr:    true,
			expErrMsg: "failed to compile CEL expression: ERROR: <input>:1:1: undeclared reference to 'actor' (in container '')\n | actor == 'test'\n | ^",
		},
	}
	for _, tc := range cases {
		tc := tc

		env, _ := cel.NewEnv(cel.Variable(AssertionKey, cel.DynType))
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
				Rule: &Rule{If: "assertion.workflow == 'Test' && assertion.actor == 'test'"},
				Scopes: map[string]*Scope{
					"test": {
						Rule: &Rule{If: "assertion.workflow == 'Test' && assertion.actor == 'test'"},
					},
				},
			},
			expErr: false,
		},
		{
			name: "failure to parse, no assertion",
			config: Config{
				Rule: &Rule{If: "actor == 'test'"},
				Scopes: map[string]*Scope{
					"test": {
						Rule: &Rule{If: "assertion.actor == 'test'"},
					},
				},
			},
			expErr:    true,
			expErrMsg: "failed to compile CEL expression: ERROR: <input>:1:1: undeclared reference to 'actor' (in container '')\n | actor == 'test'\n | ^",
		},
	}
	for _, tc := range cases {
		tc := tc

		env, _ := cel.NewEnv(cel.Variable(AssertionKey, cel.DynType))
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

func TestRuleEval(t *testing.T) {
	t.Parallel()

	token := map[string]any{
		"jti":                   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
		"sub":                   "repo:abcxyz/test:ref:refs/heads/main",
		"aud":                   "https://github.com/abcxyz",
		"ref":                   "refs/heads/main",
		"sha":                   "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"repository":            "abcxyz/test",
		"repository_owner":      "abcxyz",
		"repository_owner_id":   "111111111",
		"run_id":                "1111111111",
		"run_number":            "11",
		"run_attempt":           "1",
		"repository_visibility": "private",
		"repository_id":         "111111111",
		"actor_id":              "1111111",
		"actor":                 "test",
		"workflow":              "Test",
		"head_ref":              "",
		"base_ref":              "",
		"event_name":            "workflow_dispatch",
		"ref_type":              "branch",
		"workflow_ref":          "abcxyz/test/.github/workflows/test.yaml@refs/heads/main",
		"workflow_sha":          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"job_workflow_ref":      "abcxyz/test/.github/workflows/test.yaml@refs/heads/main",
		"job_workflow_sha":      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		"iss":                   "https://token.actions.githubusercontent.com",
		"nbf":                   "1669925693",
		"exp":                   "1669926893",
	}

	cases := []struct {
		name      string
		rule      *Rule
		token     map[string]interface{}
		want      bool
		expErr    bool
		expErrMsg string
	}{
		{
			name: "success",
			rule: &Rule{
				If: "assertion.workflow == 'Test'",
			},
			token:     token,
			want:      true,
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "success using issuers var",
			rule: &Rule{
				If: "assertion.iss == issuers.github",
			},
			token:     token,
			want:      true,
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "bad issuer",
			rule: &Rule{
				If: "assertion.iss == issuers.unknown",
			},
			token:     token,
			want:      false,
			expErr:    true,
			expErrMsg: "failed to evaluate CEL expression: no such key: unknown",
		},
		{
			name: "no match",
			rule: &Rule{
				If: "assertion.workflow == 'not valid'",
			},
			token:     token,
			want:      false,
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "bad assertion",
			rule: &Rule{
				If: "assertion.doesntexist == 'not valid'",
			},
			token:     token,
			want:      false,
			expErr:    true,
			expErrMsg: "failed to evaluate CEL expression: no such key: doesntexist",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env, err := cel.NewEnv(cel.Variable(AssertionKey, cel.DynType), cel.Variable(IssuersKey, cel.DynType))
			if err != nil {
				t.Errorf("failed to create CEL environment: %v", err)
			}

			if err = tc.rule.compile(env); err != nil {
				t.Errorf("failed to compile rule: %v", err)
			}

			got, err := tc.rule.eval(tc.token)
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Error(msg)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
