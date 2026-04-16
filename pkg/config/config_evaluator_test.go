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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/go-cmp/cmp"

	"github.com/abcxyz/github-token-minter/pkg/policy"
	"github.com/abcxyz/pkg/testutil"
)

type testConfigFileLoader struct {
	result     *Config
	err        error
	sourceType string
}

func (l *testConfigFileLoader) Load(ctx context.Context, org, repo string) (*Config, error) {
	return l.result, l.err
}

func (l *testConfigFileLoader) Source(org, repo string) string {
	return fmt.Sprintf("mem://%s/%s", org, repo)
}

func (l *testConfigFileLoader) SourceType() string {
	if l.sourceType != "" {
		return l.sourceType
	}
	return "test"
}

func TestOrderedConfigFileLoader(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(cel.Variable(AssertionKey, cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		reader    ConfigEvaluator
		org       string
		repo      string
		scope     string
		token     interface{}
		want      *Scope
		expErr    bool
		expErrMsg string
	}{
		{
			name: "single child with result",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: &Config{
								Scopes: map[string]*Scope{
									"test_scope": {Rule: &Rule{If: "assertion.target == '1234'"}},
								},
							},
							err: nil,
						},
					},
				},
			},
			org:   "test_org",
			repo:  "test_repo",
			scope: "test_scope",
			token: map[string]string{"target": "1234"},
			want: &Scope{Rule: &Rule{
				If: "assertion.target == '1234'",
			}},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "single child with error",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: nil,
							err:    fmt.Errorf("test_error"),
						},
					},
				},
			},
			org:       "test_org",
			repo:      "test_repo",
			scope:     "test_scope",
			token:     map[string]string{},
			want:      nil,
			expErr:    true,
			expErrMsg: "error reading configuration, exhausted all possible source locations, failed to locate scope [test_scope] for repository [test_org/test_repo].\nEvaluation results:\n[mem://test_org/test_repo]: error reading configuration, child reader threw error: compiling config loader, sub loader failed to load configuration: test_error",
		},
		{
			name: "multiple children with result in first",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: &Config{Scopes: map[string]*Scope{
								"test_scope": {Rule: &Rule{If: "assertion.target == '1234'"}},
							}},
							err: nil,
						},
					},
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: &Config{Scopes: map[string]*Scope{
								"test_scope": {Rule: &Rule{If: "assertion.target == '5678'"}},
							}},
							err: nil,
						},
					},
				},
			},
			org:   "test_org",
			repo:  "test_repo",
			scope: "test_scope",
			token: map[string]string{"target": "1234"},
			want: &Scope{
				Rule: &Rule{
					If: "assertion.target == 1234",
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "multiple children with error in first",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: nil,
							err:    fmt.Errorf("test_error"),
						},
					},
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: nil,
							err:    nil,
						},
					},
				},
			},
			org:       "test_org",
			repo:      "test_repo",
			scope:     "test_scope",
			token:     map[string]string{},
			want:      nil,
			expErr:    true,
			expErrMsg: "error reading configuration, exhausted all possible source locations, failed to locate scope [test_scope] for repository [test_org/test_repo].\nEvaluation results:\n[mem://test_org/test_repo]: error reading configuration, child reader threw error: compiling config loader, sub loader failed to load configuration: test_error",
		},
		{
			name: "multiple children with result in second",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: nil,
							err:    nil,
						},
					},
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: &Config{Scopes: map[string]*Scope{
								"test_scope": {Rule: &Rule{If: "assertion.target == '1234'"}},
							}},
							err: nil,
						},
					},
				},
			},
			org:   "test_org",
			repo:  "test_repo",
			scope: "test_scope",
			token: map[string]string{"target": "1234"},
			want: &Scope{
				Rule: &Rule{
					If: "assertion.target == '1234'",
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "multiple children with error in second",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: nil,
							err:    nil,
						},
					},
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: nil,
							err:    fmt.Errorf("test_error"),
						},
					},
				},
			},
			org:       "test_org",
			repo:      "test_repo",
			scope:     "test_scope",
			token:     map[string]string{},
			want:      nil,
			expErr:    true,
			expErrMsg: "error reading configuration, exhausted all possible source locations, failed to locate scope [test_scope] for repository [test_org/test_repo].\nEvaluation results:\n[mem://test_org/test_repo]: error reading configuration, child reader threw error: compiling config loader, sub loader failed to load configuration: test_error",
		},
		{
			name: "multiple children with no results",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: nil,
							err:    nil,
						},
					},
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: nil,
							err:    nil,
						},
					},
				},
			},
			org:       "test_org",
			repo:      "test_repo",
			scope:     "test_scope",
			token:     map[string]string{},
			want:      nil,
			expErr:    true,
			expErrMsg: "error reading configuration, exhausted all possible source locations, failed to locate scope [test_scope] for repository [test_org/test_repo].\nEvaluation results:\n[mem://test_org/test_repo]: config not found\n[mem://test_org/test_repo]: config not found",
		},
		{
			name: "v1 config match first",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: &Config{
								Version: configVersionV1,
								Scopes: map[string]*Scope{
									"default_00000000": {Rule: &Rule{If: "assertion.target == '1234'"}},
									"default_00000001": {Rule: &Rule{If: "assertion.target == '5678'"}},
								},
							},
							err: nil,
						},
					},
				},
			},
			org:   "test_org",
			repo:  "test_repo",
			scope: "test_scope",
			token: map[string]string{"target": "1234"},
			want: &Scope{
				Rule: &Rule{
					If: "assertion.target == '1234'",
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "v1 config match second",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: &Config{
								Version: configVersionV1,
								Scopes: map[string]*Scope{
									"default_00000000": {Rule: &Rule{If: "assertion.target == '1234'"}},
									"default_00000001": {Rule: &Rule{If: "assertion.target == '5678'"}},
								},
							},
							err: nil,
						},
					},
				},
			},
			org:   "test_org",
			repo:  "test_repo",
			scope: "test_scope",
			token: map[string]string{"target": "5678"},
			want: &Scope{
				Rule: &Rule{
					If: "assertion.target == '5678'",
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "v1 config match none",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: &Config{
								Version: configVersionV1,
								Scopes: map[string]*Scope{
									"default_00000000": {Rule: &Rule{If: "assertion.target == '1234'"}},
									"default_00000001": {Rule: &Rule{If: "assertion.target == '5678'"}},
								},
							},
							err: nil,
						},
					},
				},
			},
			org:       "test_org",
			repo:      "test_repo",
			scope:     "test_scope",
			token:     map[string]string{"target": "9999"},
			want:      nil,
			expErr:    true,
			expErrMsg: "error reading configuration, exhausted all possible source locations, failed to locate scope [test_scope] for repository [test_org/test_repo].\nEvaluation results:\n[mem://test_org/test_repo]: no matching scope found in v1 config",
		},
		{
			name: "multiple children with scopes, result in second",
			reader: &configEvaluator{
				loaders: []ConfigFileLoader{
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: &Config{Scopes: map[string]*Scope{
								"not_the_test_scope": {Rule: &Rule{If: "assertion.target == '1234'"}},
							}},
							err: nil,
						},
					},
					&compilingConfigLoader{
						env: env, loader: &testConfigFileLoader{
							result: &Config{Scopes: map[string]*Scope{
								"test_scope": {Rule: &Rule{If: "assertion.target == '5678'"}},
							}},
							err: nil,
						},
					},
				},
			},
			org:   "test_org",
			repo:  "test_repo",
			scope: "test_scope",
			token: map[string]string{"target": "5678"},
			want: &Scope{
				Rule: &Rule{
					If: "assertion.target == 5678",
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
	}

	ctx := t.Context()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, _, err := tc.reader.Eval(ctx, tc.org, tc.repo, tc.scope, tc.token)
			if diff := cmp.Diff(tc.want, got, cmp.FilterPath(func(p cmp.Path) bool {
				return p.Last().String() != "Program"
			}, cmp.Ignore())); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatal(msg)
			}
			if !tc.expErr && got == nil {
				t.Errorf("program nil without error")
			}
		})
	}
}

func TestConfigEvaluator_Policy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	rego := `
package minty.policy
deny contains "test source not allowed" if {
    input.source == "test"
}
`
	err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(rego), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	eval, err := policy.LoadPolicies(dir)
	if err != nil {
		t.Fatal(err)
	}

	ce := &configEvaluator{
		loaders: []ConfigFileLoader{
			&testConfigFileLoader{
				result: &Config{Scopes: map[string]*Scope{"test_scope": {}}},
				err:    nil,
			},
		},
		policy: eval,
	}

	ctx := t.Context()

	_, _, err = ce.Eval(ctx, "test_org", "test_repo", "test_scope", map[string]string{})
	if err == nil {
		t.Fatal("expected error due to policy violation, got nil")
	}

	if !strings.Contains(err.Error(), "policy violation: test source not allowed") {
		t.Errorf("expected error to contain 'policy violation: test source not allowed', got %v", err)
	}
}

func TestConfigEvaluator_SpecificPolicies(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	// Load policies from the top-level directory
	policyDir := "../../policy"
	eval, err := policy.LoadPolicies(policyDir)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name        string
		sourceType  string
		config      *Config
		requestRepo string
		token       any
		wantErr     string
	}{
		{
			name:       "read_only_ok",
			sourceType: "local",
			config: &Config{
				Scopes: map[string]*Scope{
					"test": {
						Permissions: map[string]string{"contents": "read"},
					},
				},
			},
			requestRepo: "test_repo",
			wantErr:     "",
		},
		{
			name:       "read_only_violation",
			sourceType: "local",
			config: &Config{
				Scopes: map[string]*Scope{
					"test": {
						Permissions: map[string]string{"contents": "write"},
					},
				},
			},
			requestRepo: "test_repo",
			wantErr:     "requests non-read permission",
		},
		{
			name:       "read_only_violation_empty_permissions",
			sourceType: "local",
			config: &Config{
				Scopes: map[string]*Scope{
					"test": {
						Permissions: map[string]string{},
					},
				},
			},
			requestRepo: "test_repo",
			wantErr:     "has empty permissions",
		},
		{
			name:       "centralized_ok_same_repo",
			sourceType: "local",
			config: &Config{
				Scopes: map[string]*Scope{
					"test": {
						Repositories: []string{"test_repo"},
					},
				},
			},
			requestRepo: "test_repo",
			wantErr:     "",
		},
		{
			name:       "centralized_violation_cross_repo",
			sourceType: "local",
			config: &Config{
				Scopes: map[string]*Scope{
					"test": {
						Repositories: []string{"other_repo"},
					},
				},
			},
			requestRepo: "test_repo",
			wantErr:     "requests access to other repository",
		},
		{
			name:       "centralized_ok_cross_repo_from_central",
			sourceType: "central",
			config: &Config{
				Scopes: map[string]*Scope{
					"test": {
						Repositories: []string{"other_repo"},
					},
				},
			},
			requestRepo: "test_repo",
			wantErr:     "",
		},
		{
			name:       "fail_safe_ok",
			sourceType: "local",
			config: &Config{
				Scopes: map[string]*Scope{
					"test": {},
				},
			},
			requestRepo: "test_repo",
			token: map[string]any{
				"enterprise_id":       "YOUR_ENTERPRISE_ID",
				"repository_owner_id": "YOUR_ORG_ID",
				"repository_id":       "YOUR_REPO_ID",
			},
			wantErr: "",
		},
		{
			name:       "fail_safe_violation_org",
			sourceType: "local",
			config: &Config{
				Scopes: map[string]*Scope{
					"test": {},
				},
			},
			requestRepo: "test_repo",
			token: map[string]any{
				"enterprise_id":       "YOUR_ENTERPRISE_ID",
				"repository_owner_id": "WRONG_ORG_ID",
				"repository_id":       "YOUR_REPO_ID",
			},
			wantErr: "invalid org ID",
		},
		{
			name:       "fail_safe_violation_missing_org",
			sourceType: "local",
			config: &Config{
				Scopes: map[string]*Scope{
					"test": {},
				},
			},
			requestRepo: "test_repo",
			token: map[string]any{
				"enterprise_id": "YOUR_ENTERPRISE_ID",
				"repository_id": "YOUR_REPO_ID",
			},
			wantErr: "invalid org ID",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ce := &configEvaluator{
				loaders: []ConfigFileLoader{
					&testConfigFileLoader{
						result:     tc.config,
						err:        nil,
						sourceType: tc.sourceType,
					},
				},
				policy: eval,
			}

			_, _, err := ce.Eval(ctx, "test_org", tc.requestRepo, "test", tc.token)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected error to contain %q, got %v", tc.wantErr, err)
				}
			}
		})
	}
}
