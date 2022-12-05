// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package config

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPermissionsConfig_Parser(t *testing.T) {
	t.Parallel()

	configBadYaml := `
{"something": "maybe json"}
	`
	configSinglePermission := `
id: 'test'
permissions: 
  - if: 'test=somevalue'
    repository:
      - 'abcxyz/breakglass'
    scope:
      - 'pull_request:write'
`
	configMultiplePermissions := `
permissions: 
  - if: 'test=somevalue'
    repository:
      - 'abcxyz/breakglass'
    scope:
      - 'pull_request:write'
  - if: 'true'
    repository:
      - 'abcxyz/pkg'
    scope:
      - 'issues:write'
`
	configMultipleRepositories := `
permissions: 
  - if: 'test=somevalue'
    repository:
      - 'abcxyz/breakglass'
      - 'abcxyz/pkg'
    scope:
      - 'pull_request:write'
`
	configMultipleScopes := `
permissions: 
  - if: 'test=somevalue'
    repository:
      - 'abcxyz/breakglass'
    scope:
      - 'pull_request:write'
      - 'issues:write'
`
	configLarge := `
permissions: 
  - if: 'test=somevalue'
    repository:
      - 'abcxyz/breakglass'
    scope:
      - 'issues:read'
      - 'pull_request:write'
  - if: 'test=someothervalue'
    repository:
      - 'abcxyz/pkg'
      - 'abcxyz/.github'
    scope:
      - 'issues:read'
      - 'pull_request:write'
  - if: 'true'
    repository:
      - 'abcxyz/pkg'
      - 'abcxyz/.github'
      - 'abcxyz/breakglass'
    scope:
      - 'issues:read'
`

	cases := []struct {
		name      string
		content   string
		expect    *PermissionsConfig
		wantError bool
	}{
		{
			name:      "bad yaml",
			content:   configBadYaml,
			expect:    nil,
			wantError: true,
		},
		{
			name:    "single permission",
			content: configSinglePermission,
			expect: &PermissionsConfig{
				Id: "test",
				Permissions: []Permission{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass"}, Scopes: []string{"pull_request:write"}},
				},
			},
			wantError: false,
		},
		{
			name:    "multiple permissions",
			content: configMultiplePermissions,
			expect: &PermissionsConfig{
				Permissions: []Permission{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass"}, Scopes: []string{"pull_request:write"}},
					{If: "true", Repositories: []string{"abcxyz/pkg"}, Scopes: []string{"issues:write"}},
				},
			},
			wantError: false,
		},
		{
			name:    "multiple repositories",
			content: configMultipleRepositories,
			expect: &PermissionsConfig{
				Permissions: []Permission{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass", "abcxyz/pkg"}, Scopes: []string{"pull_request:write"}},
				},
			},
			wantError: false,
		},
		{
			name:    "multiple scopes",
			content: configMultipleScopes,
			expect: &PermissionsConfig{
				Permissions: []Permission{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass"}, Scopes: []string{"pull_request:write", "issues:write"}},
				},
			},
			wantError: false,
		},
		{
			name:    "multiple permissions, scopes and repos",
			content: configLarge,
			expect: &PermissionsConfig{
				Permissions: []Permission{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass"}, Scopes: []string{"issues:read", "pull_request:write"}},
					{If: "test=someothervalue", Repositories: []string{"abcxyz/pkg", "abcxyz/.github"}, Scopes: []string{"issues:read", "pull_request:write"}},
					{If: "true", Repositories: []string{"abcxyz/pkg", "abcxyz/.github", "abcxyz/breakglass"}, Scopes: []string{"issues:read"}},
				},
			},
			wantError: false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			parser := NewConfigParser()
			results, err := parser.parse(strings.NewReader(tc.content))
			if tc.wantError != (err != nil) {
				t.Errorf("expected error want: %#v, got: %#v - error: %v", tc.wantError, err != nil, err)
			}
			if diff := cmp.Diff(tc.expect, results); diff != "" {
				t.Errorf("results (-want,+got):\n%s", diff)
			}
		})
	}
}
