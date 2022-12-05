package permissions

import (
	"testing"

	"github.com/abcxyz/minty/pkg/config"
	"github.com/google/go-cmp/cmp"
)

func TestGetPermissionsForToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		pc        *config.PermissionsConfig
		token     map[string]string
		want      *config.Permission
		expErr    bool
		expErrMsg string
	}{{
		name: "success",
		pc: &config.PermissionsConfig{
			Permissions: []config.Permission{
				{
					If:           "jwt.workflow == 'Test' && jwt.actor == 'verbanicm'",
					Repositories: []string{"*"},
					Scopes:       []string{"issues:write", "pull_requests:read"},
				},
				{
					If:           "true",
					Repositories: []string{"abcxyz/breakglass"},
					Scopes:       []string{"issues:read"},
				},
			},
		},
		token: map[string]string{
			"workflow": "Test",
			"actor":    "verbanicm",
		},
		want: &config.Permission{
			If:           "jwt.workflow == 'Test' && jwt.actor == 'verbanicm'",
			Repositories: []string{"*"},
			Scopes:       []string{"issues:write", "pull_requests:read"},
		},
	}, {
		name: "success_catch_all",
		pc: &config.PermissionsConfig{
			Permissions: []config.Permission{
				{
					If:           "jwt.workflow == 'Test' && jwt.actor == 'verbanicm'",
					Repositories: []string{"*"},
					Scopes:       []string{"issues:write", "pull_requests:read"},
				},
				{
					If:           "true",
					Repositories: []string{"abcxyz/breakglass"},
					Scopes:       []string{"issues:read"},
				},
			},
		},
		token: map[string]string{
			"workflow": "Doesnt Exist",
			"actor":    "fakeuser",
		},
		want: &config.Permission{
			If:           "true",
			Repositories: []string{"abcxyz/breakglass"},
			Scopes:       []string{"issues:read"},
		},
	}, {
		name: "success_cel_function",
		pc: &config.PermissionsConfig{
			Permissions: []config.Permission{
				{
					If:           "jwt.workflow_ref.startsWith('abcxyz/breakglass/.github/workflows/test.yaml') && jwt.actor == 'verbanicm'",
					Repositories: []string{"*"},
					Scopes:       []string{"issues:write", "pull_requests:read"},
				},
				{
					If:           "true",
					Repositories: []string{"abcxyz/breakglass"},
					Scopes:       []string{"issues:read"},
				},
			},
		},
		token: map[string]string{
			"workflow_ref": "abcxyz/breakglass/.github/workflows/test.yaml@refs/heads/main",
			"actor":        "verbanicm",
		},
		want: &config.Permission{
			If:           "jwt.workflow_ref.startsWith('abcxyz/breakglass/.github/workflows/test.yaml') && jwt.actor == 'verbanicm'",
			Repositories: []string{"*"},
			Scopes:       []string{"issues:write", "pull_requests:read"},
		},
	}, {
		name: "error_key_doesnt_exist",
		pc: &config.PermissionsConfig{
			Permissions: []config.Permission{
				{
					If:           "jwt.doesntexist == 'dne'",
					Repositories: []string{"*"},
					Scopes:       []string{"issues:write", "pull_requests:read"},
				},
			},
		},
		token: map[string]string{
			"actor": "verbanicm",
		},
		expErr:    true,
		expErrMsg: "failed to evaluate CEL expression: no such key: doesntexist",
	}, {
		name: "error_no_permissions",
		pc: &config.PermissionsConfig{
			Permissions: []config.Permission{
				{
					If:           "jwt.actor == 'verbanicm'",
					Repositories: []string{"*"},
					Scopes:       []string{"issues:write", "pull_requests:read"},
				},
			},
		},
		token: map[string]string{
			"actor": "wronguser",
		},
		expErr:    true,
		expErrMsg: "no permissions found",
	}}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetPermissionsForToken(tc.pc, tc.token)
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
