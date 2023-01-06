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

			got, err := permissionsForToken(context.Background(), tc.pc, tc.token)
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
