package permissions

import (
	"context"
	"testing"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/google/go-cmp/cmp"
)

var TestJWT = map[string]interface{}{
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
		pc        *config.RepositoryConfig
		token     map[string]interface{}
		want      *config.Config
		expErr    bool
		expErrMsg string
	}{{
		name: "success",
		pc: &config.RepositoryConfig{
			Config: []config.Config{
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
		},
		token: TestJWT,
		want: &config.Config{
			If:           "assertion.workflow == 'Test' && assertion.actor == 'test'",
			Repositories: []string{"*"},
			Permissions:  map[string]string{"issues": "write", "pull_requests": "write"},
		},
	}, {
		name: "success_catch_all",
		pc: &config.RepositoryConfig{
			Config: []config.Config{
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
		},
		token: TestJWT,
		want: &config.Config{
			If:           "true",
			Repositories: []string{"abcxyz/test"},
			Permissions:  map[string]string{"issues": "read"},
		},
	}, {
		name: "success_cel_function",
		pc: &config.RepositoryConfig{
			Config: []config.Config{
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
		},
		token: TestJWT,
		want: &config.Config{
			If:           "assertion.workflow_ref.startsWith('abcxyz/test/.github/workflows/test.yaml') && assertion.actor == 'test'",
			Repositories: []string{"*"},
			Permissions:  map[string]string{"issues": "write", "pull_requests": "read"},
		},
	}, {
		name: "error_key_doesnt_exist",
		pc: &config.RepositoryConfig{
			Config: []config.Config{
				{
					If:           "assertion.doesntexist == 'doesntexist'",
					Repositories: []string{"*"},
					Permissions:  map[string]string{"issues": "write", "pull_requests": "read"},
				},
			},
		},
		token:     TestJWT,
		expErr:    true,
		expErrMsg: "failed to evaluate CEL expression: no such key: doesntexist",
	}, {
		name: "error_no_permissions",
		pc: &config.RepositoryConfig{
			Config: []config.Config{
				{
					If:           "assertion.actor == 'user'",
					Repositories: []string{"*"},
					Permissions:  map[string]string{"issues": "write", "pull_requests": "write"},
				},
			},
		},
		token:     TestJWT,
		expErr:    true,
		expErrMsg: "no permissions found",
	}}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetPermissionsForToken(context.Background(), tc.pc, tc.token)
			if (err != nil) != tc.expErr {
				t.Fatal(err)
			}

			if tc.expErr && tc.expErrMsg != err.Error() {
				t.Fatalf("expected error mismatch want: %s, got: %s", tc.expErrMsg, err)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
