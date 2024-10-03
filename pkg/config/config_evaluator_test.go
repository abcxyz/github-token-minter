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
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/go-cmp/cmp"

	"github.com/abcxyz/pkg/testutil"
)

type testConfigFileLoader struct {
	result *Config
	err    error
}

func (l *testConfigFileLoader) Load(ctx context.Context, org, repo string) (*Config, error) {
	return l.result, l.err
}

func (l *testConfigFileLoader) Source(org, repo string) string {
	return fmt.Sprintf("mem://%s/%s", org, repo)
}

func TestOrderedConfigFileLoader(t *testing.T) {
	t.Parallel()

	env, err := cel.NewEnv(cel.Variable(assertionKey, cel.DynType))
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
			expErrMsg: "error reading configuration, child reader threw error: compiling config loader, sub loader failed to load configuration: test_error",
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
			expErrMsg: "error reading configuration, child reader threw error: compiling config loader, sub loader failed to load configuration: test_error",
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
			expErrMsg: "error reading configuration, child reader threw error: compiling config loader, sub loader failed to load configuration: test_error",
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
			expErrMsg: "error reading configuration, exhausted all possible source locations",
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
			expErrMsg: "error reading configuration, exhausted all possible source locations",
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

	ctx := context.Background()
	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, _, err := tc.reader.Eval(ctx, tc.org, tc.repo, tc.scope, tc.token)
			if diff := cmp.Diff(tc.want, got, cmp.FilterPath(func(p cmp.Path) bool {
				return !(p.Last().String() == "Program")
			}, cmp.Ignore())); diff != "" {
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
