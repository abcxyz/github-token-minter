// Copyright 2023 The Authors (see AUTHORS file)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package server

import (
	"context"
	"testing"

	"github.com/abcxyz/pkg/testutil"
	"github.com/google/cel-go/cel"
	"github.com/google/go-cmp/cmp"
)

var testJWT = map[string]interface{}{
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

func TestCompileExpression(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		expr      string
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "success",
			expr:      "assertion.workflow == 'Test' && assertion.actor == 'test'",
			expErr:    false,
			expErrMsg: "",
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

func TestGetPermissionsForToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		pc        *RepositoryConfig
		token     map[string]interface{}
		want      *Config
		expErr    bool
		expErrMsg string
	}{{
		name: "success",
		pc: &RepositoryConfig{
			{
				If:           "assertion.workflow == 'Test' && assertion.actor == 'test'",
				Repositories: []string{"*"},
				Permissions:  map[string]string{"issues": "write", "pull_requests": "write"},
			},
			{
				If:           "true",
				Repositories: []string{"abcxyz/test"},
				Permissions:  map[string]string{"issues": "read"},
			},
		},
		token: testJWT,
		want: &Config{
			If:           "assertion.workflow == 'Test' && assertion.actor == 'test'",
			Repositories: []string{"*"},
			Permissions:  map[string]string{"issues": "write", "pull_requests": "write"},
		},
	}, {
		name: "success_catch_all",
		pc: &RepositoryConfig{
			{
				If:           "assertion.workflow == 'Test' && assertion.actor == 'user'",
				Repositories: []string{"*"},
				Permissions:  map[string]string{"issues": "write", "pull_requests": "write"},
			},
			{
				If:           "true",
				Repositories: []string{"abcxyz/test"},
				Permissions:  map[string]string{"issues": "read"},
			},
		},
		token: testJWT,
		want: &Config{
			If:           "true",
			Repositories: []string{"abcxyz/test"},
			Permissions:  map[string]string{"issues": "read"},
		},
	}, {
		name: "success_cel_function",
		pc: &RepositoryConfig{
			{
				If:           "assertion.workflow_ref.startsWith('abcxyz/test/.github/workflows/test.yaml') && assertion.actor == 'test'",
				Repositories: []string{"*"},
				Permissions:  map[string]string{"issues": "write", "pull_requests": "read"},
			},
			{
				If:           "true",
				Repositories: []string{"abcxyz/test"},
				Permissions:  map[string]string{"issues": "read"},
			},
		},
		token: testJWT,
		want: &Config{
			If:           "assertion.workflow_ref.startsWith('abcxyz/test/.github/workflows/test.yaml') && assertion.actor == 'test'",
			Repositories: []string{"*"},
			Permissions:  map[string]string{"issues": "write", "pull_requests": "read"},
		},
	}, {
		name: "error_key_doesnt_exist",
		pc: &RepositoryConfig{
			{
				If:           "assertion.doesntexist == 'doesntexist'",
				Repositories: []string{"*"},
				Permissions:  map[string]string{"issues": "write", "pull_requests": "read"},
			},
		},
		token:     testJWT,
		expErr:    true,
		expErrMsg: "failed to evaluate CEL expression: no such key: doesntexist",
	}, {
		name: "error_no_permissions",
		pc: &RepositoryConfig{
			{
				If:           "assertion.actor == 'user'",
				Repositories: []string{"*"},
				Permissions:  map[string]string{"issues": "write", "pull_requests": "write"},
			},
		},
		token:     testJWT,
		expErr:    true,
		expErrMsg: "no permissions found",
	}}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := compileExpressions(tc.pc)
			if err != nil {
				t.Fatalf("expressions failed to compile")
			}
			got, err := permissionsForToken(context.Background(), tc.pc, tc.token)
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}

			// It is nearly impossible to diff the Program object
			// and we don't really care about the Program itself in
			// this test so remove it from the object.
			if got != nil {
				got.Program = nil
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestValidatePermissions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		allowed   map[string]string
		requested map[string]string
		expErrMsg string
	}{
		{
			name:      "success",
			allowed:   map[string]string{"issues": "write"},
			requested: map[string]string{"issues": "write"},
			expErrMsg: "",
		}, {
			name:      "request lesser permission",
			allowed:   map[string]string{"issues": "write"},
			requested: map[string]string{"issues": "read"},
			expErrMsg: "",
		}, {
			name:      "request permission not authorized",
			allowed:   map[string]string{},
			requested: map[string]string{"issues": "read"},
			expErrMsg: "requested permission 'issues' is not authorized",
		}, {
			name:      "request multiple permissions success",
			allowed:   map[string]string{"issues": "read", "pull_requests": "write"},
			requested: map[string]string{"issues": "read", "pull_requests": "write"},
			expErrMsg: "",
		}, {
			name:      "request multiple permissions with lesser",
			allowed:   map[string]string{"issues": "read", "pull_requests": "write"},
			requested: map[string]string{"issues": "read", "pull_requests": "read"},
			expErrMsg: "",
		}, {
			name:      "request multiple permissions with failure",
			allowed:   map[string]string{"issues": "read", "pull_requests": "write"},
			requested: map[string]string{"issues": "read", "pull_requests": "write", "workflows": "read"},
			expErrMsg: "requested permission 'worflows' is not authorized",
		}, {
			name:      "request greater permission",
			allowed:   map[string]string{"issues": "read"},
			requested: map[string]string{"issues": "write"},
			expErrMsg: "requested permission level 'write' for permission 'issues' is not authorized",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validatePermissions(context.Background(), tc.allowed, tc.requested)
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}
		})
	}
}
