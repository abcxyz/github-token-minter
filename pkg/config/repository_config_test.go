// Copyright 2022 Google LLC
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
package config

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRepositoryConfig_Parser(t *testing.T) {
	t.Parallel()

	configBadYaml := `
{"something": "maybe json"}
	`
	configSinglePermission := `
config: 
  - if: 'test=somevalue'
    repositories:
      - 'abcxyz/breakglass'
    permissions:
      pull_request: 'write'
`
	configMultiple := `
config: 
  - if: 'test=somevalue'
    repositories:
      - 'abcxyz/breakglass'
    permissions:
      pull_request: 'write'
  - if: 'true'
    repositories:
      - 'abcxyz/pkg'
    permissions:
      issues: 'write'
`
	configMultipleRepositories := `
config: 
  - if: 'test=somevalue'
    repositories:
      - 'abcxyz/breakglass'
      - 'abcxyz/pkg'
    permissions:
      pull_request: 'write'
`
	configMultiplePermissions := `
config: 
  - if: 'test=somevalue'
    repositories:
      - 'abcxyz/breakglass'
    permissions:
      pull_request: 'write'
      issues: 'write'
`
	configLarge := `
config: 
  - if: 'test=somevalue'
    repositories:
      - 'abcxyz/breakglass'
    permissions:
      issues: 'read'
      pull_request: 'write'
  - if: 'test=someothervalue'
    repositories:
      - 'abcxyz/pkg'
      - 'abcxyz/.github'
    permissions:
      issues: 'read'
      pull_request: 'write'
  - if: 'true'
    repositories:
      - 'abcxyz/pkg'
      - 'abcxyz/.github'
      - 'abcxyz/breakglass'
    permissions:
      issues: 'read'
`

	cases := []struct {
		name      string
		content   string
		expect    *RepositoryConfig
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
			expect: &RepositoryConfig{
				Config: []Config{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass"}, Permissions: map[string]string{"pull_request": "write"}},
				},
			},
			wantError: false,
		},
		{
			name:    "multiple permissions",
			content: configMultiple,
			expect: &RepositoryConfig{
				Config: []Config{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass"}, Permissions: map[string]string{"pull_request": "write"}},
					{If: "true", Repositories: []string{"abcxyz/pkg"}, Permissions: map[string]string{"issues": "write"}},
				},
			},
			wantError: false,
		},
		{
			name:    "multiple repositories",
			content: configMultipleRepositories,
			expect: &RepositoryConfig{
				Config: []Config{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass", "abcxyz/pkg"}, Permissions: map[string]string{"pull_request": "write"}},
				},
			},
			wantError: false,
		},
		{
			name:    "multiple Permissions",
			content: configMultiplePermissions,
			expect: &RepositoryConfig{
				Config: []Config{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass"}, Permissions: map[string]string{"pull_request": "write", "issues": "write"}},
				},
			},
			wantError: false,
		},
		{
			name:    "multiple permissions, Permissions and repos",
			content: configLarge,
			expect: &RepositoryConfig{
				Config: []Config{
					{If: "test=somevalue", Repositories: []string{"abcxyz/breakglass"}, Permissions: map[string]string{"issues": "read", "pull_request": "write"}},
					{If: "test=someothervalue", Repositories: []string{"abcxyz/pkg", "abcxyz/.github"}, Permissions: map[string]string{"issues": "read", "pull_request": "write"}},
					{If: "true", Repositories: []string{"abcxyz/pkg", "abcxyz/.github", "abcxyz/breakglass"}, Permissions: map[string]string{"issues": "read"}},
				},
			},
			wantError: false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			parser := NewParser()
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
