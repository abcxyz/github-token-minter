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

	"github.com/google/go-cmp/cmp"

	"github.com/abcxyz/pkg/testutil"
)

func TestConfigFileRead(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		data      string
		want      *Config
		expErr    bool
		expErrMsg string
	}{
		{
			name: "full yaml with policy and multiple scopes",
			data: `
# Only allow if the OIDC token is from GitHub and the source is this organization and repository
# Deny any request that isn't from the main branch.
# This policy is applied first before the scope is evaluated.
version: 'minty.abcxyz.dev/v2'
rule:
  if: |-
      assertion.iss = 'https://token.actions.githubusercontent.com' &&
      assertion.organization_id = '93787867' &&
      assertion.repository_id = '576289489' &&
      assertion.ref != 'refs/heads/main'

# Request level scopes that can be targeted, each scope provides a set of permissions that are available.
# The scope is looked up by name and then the validation in the "if" is applied to ensure that it matches
# the expected criteria.
scope:
  draft-release:
    rule:
      if: |-
        assertion.workflow_ref == assertion.job_workflow_ref &&
        assertion.job_workflow_ref == 'abcxyz/github-token-minter/.github/workflows/draft-release.yml@refs/heads/main' &&
        assertion.event_name == 'workflow_dispatch'
    permissions:
      contents: 'write'
      pull_requests: 'write'

  release:
    rule:
      if: |-
        assertion.workflow_ref == assertion.job_workflow_ref &&
        assertion.job_workflow_ref == 'abcxyz/github-token-minter/.github/workflows/release.yml@refs/heads/main' &&
        assertion.event_name == 'push'
    permissions:
      contents: 'write'`,
			want: &Config{
				Version: "minty.abcxyz.dev/v2",
				Rule: Rule{
					If: `assertion.iss = 'https://token.actions.githubusercontent.com' &&
assertion.organization_id = '93787867' &&
assertion.repository_id = '576289489' &&
assertion.ref != 'refs/heads/main'`,
				},
				Scopes: map[string]*Scope{
					"draft-release": {
						Rule: Rule{If: `assertion.workflow_ref == assertion.job_workflow_ref &&
assertion.job_workflow_ref == 'abcxyz/github-token-minter/.github/workflows/draft-release.yml@refs/heads/main' &&
assertion.event_name == 'workflow_dispatch'`},
						Permissions: map[string]string{"contents": "write", "pull_requests": "write"},
					},
					"release": {
						Rule: Rule{If: `assertion.workflow_ref == assertion.job_workflow_ref &&
assertion.job_workflow_ref == 'abcxyz/github-token-minter/.github/workflows/release.yml@refs/heads/main' &&
assertion.event_name == 'push'`},
						Permissions: map[string]string{"contents": "write"},
					},
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "malformed yaml",
			data:      `malformed 'yaml'`,
			want:      nil,
			expErr:    true,
			expErrMsg: "error parsing yaml document:",
		},
		{
			name:      "empty config",
			data:      `notareal: 'tag'`,
			want:      &Config{Version: latestConfigVersion},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "unsupported version",
			data:      `version: 'turbo'`,
			want:      nil,
			expErr:    true,
			expErrMsg: "unsupported configuration document version",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := read([]byte(tc.data))
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}
			if !tc.expErr && got == nil {
				t.Errorf("program nil without error")
			}
		})
	}
}
