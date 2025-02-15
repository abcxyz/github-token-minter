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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v64/github"

	"github.com/abcxyz/pkg/testutil"
)

func TestGitHubInRepoConfigFileLoader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		handler   http.HandlerFunc
		org       string
		repo      string
		path      string
		ref       string
		want      *Config
		expErr    bool
		expErrMsg string
	}{
		{
			name: "empty content",
			org:  "test_org",
			repo: "test_repo",
			path: "minty.yaml",
			ref:  "main",
			handler: func(w http.ResponseWriter, r *http.Request) {
				content := github.RepositoryContent{}
				raw, err := json.Marshal(content)
				if err != nil {
					w.WriteHeader(500)
					fmt.Fprint(w, "error marshalling yaml")
				}
				w.WriteHeader(200)
				fmt.Fprint(w, string(raw))
			},
			want:      &Config{},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "valid content",
			org:  "test_org",
			repo: "test_repo",
			path: "minty.yaml",
			ref:  "main",
			handler: func(w http.ResponseWriter, r *http.Request) {
				yaml := `
version: 'minty.abcxyz.dev/v2'
rule:
  if: 'a == b'

scope:
  test:
    rule:
      if: 'a != b'
    permissions:
      contents: 'read'`
				content := github.RepositoryContent{Content: &yaml}
				raw, err := json.Marshal(content)
				if err != nil {
					w.WriteHeader(500)
					fmt.Fprint(w, "error marshalling yaml")
				}
				w.WriteHeader(200)
				fmt.Fprint(w, string(raw))
			},
			want: &Config{
				Version: "minty.abcxyz.dev/v2",
				Rule: &Rule{
					If: "a == b",
				},
				Scopes: map[string]*Scope{
					"test": {
						Rule: &Rule{
							If: "a != b",
						},
						Permissions: map[string]string{
							"contents": "read",
						},
					},
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "ensure ref set",
			org:  "test_org",
			repo: "test_repo",
			path: "minty.yaml",
			ref:  "main",
			handler: func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				ref := query.Get("ref")
				yaml := fmt.Sprintf(`
version: 'minty.abcxyz.dev/v2'
rule:
  if: 'ref == %s'
`, ref)
				content := github.RepositoryContent{
					Content: &yaml,
				}
				raw, err := json.Marshal(content)
				if err != nil {
					w.WriteHeader(500)
					fmt.Fprint(w, "error marshalling yaml")
				}
				w.WriteHeader(200)
				fmt.Fprint(w, string(raw))
			},
			want: &Config{
				Version: "minty.abcxyz.dev/v2",
				Rule: &Rule{
					If: "ref == main",
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "api error",
			org:  "test_org",
			repo: "test_repo",
			path: "minty.yaml",
			ref:  "main",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
				fmt.Fprint(w, "I'm broke")
			},
			want:      nil,
			expErr:    true,
			expErrMsg: "error reading configuration file @ test_org/test_repo/minty.yaml",
		},
		{
			name: "file not found",
			org:  "test_org",
			repo: "test_repo",
			path: "minty.yaml",
			ref:  "main",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
				fmt.Fprint(w, "not found")
			},
			want:      nil,
			expErr:    false,
			expErrMsg: "",
		},
	}

	ctx := t.Context()
	for _, tc := range cases {
		mux := http.NewServeMux()
		mux.Handle("/api/v3/repos/test_org/test_repo/contents/minty.yaml", tc.handler)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		client, _ := github.NewClient(nil).WithEnterpriseURLs(srv.URL, srv.URL)

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			loader := ghInRepoConfigFileLoader{
				configPath: tc.path,
				ref:        tc.ref,
				provider: func(ctx context.Context, org, repo string) (*github.Client, error) {
					return client, nil
				},
			}

			got, err := loader.Load(ctx, tc.org, tc.repo)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatal(msg)
			}
			if !tc.expErr && got == nil && tc.want != nil {
				t.Errorf("program nil without error")
			}
		})
	}
}

func TestRead(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		contents  string
		want      *Config
		expErr    bool
		expErrMsg string
	}{
		{
			name: "success_v2",
			contents: `
version: 'minty.abcxyz.dev/v2'
rule:
  if: 'a == b'

scope:
  test:
    rule:
      if: 'a != b'
    permissions:
      contents: 'read'`,
			want: &Config{
				Version: configVersionV2,
				Rule:    &Rule{If: "a == b"},
				Scopes: map[string]*Scope{
					"test": {
						Rule: &Rule{If: "a != b"},
						Permissions: map[string]string{
							"contents": "read",
						},
					},
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name: "success_v1",
			contents: `
- if: 'a == b'
  repositories:
    - 'github-token-minter'
  permissions:
    contents: 'read'
- if: 'c == b'
  repositories:
    - 'abc'
  permissions:
    contents: 'write'`,
			want: &Config{
				Version: "minty.abcxyz.dev/v1",
				Rule:    &Rule{If: "true"},
				Scopes: map[string]*Scope{
					"default_00000000": {
						Rule: &Rule{
							If: "a == b",
						},
						Permissions: map[string]string{
							"contents": "read",
						},
						Repositories: []string{"github-token-minter"},
					},
					"default_00000001": {
						Rule: &Rule{
							If: "c == b",
						},
						Permissions: map[string]string{
							"contents": "write",
						},
						Repositories: []string{"abc"},
					},
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := Read([]byte(tc.contents))
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatal(msg)
			}
		})
	}
}

func TestConfigFileLoaderSource(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		loader ConfigFileLoader
		org    string
		repo   string
		want   string
	}{
		{
			name:   "local config loader",
			loader: &localConfigFileLoader{configDir: "test"},
			org:    "test_org",
			repo:   "test_repo",
			want:   "file://test/test_org/test_repo.yaml",
		},
		{
			name:   "in repo config loader",
			loader: &ghInRepoConfigFileLoader{configPath: ".test/minty.yaml"},
			org:    "test_org",
			repo:   "test_repo",
			want:   "https://github.com/test_org/test_repo/.test/minty.yaml",
		},
		{
			name:   "fixed repo config loader",
			loader: &fixedRepoConfigFileLoader{repo: "not_test_repo", loader: &ghInRepoConfigFileLoader{configPath: "minty.yaml"}},
			org:    "test_org",
			repo:   "test_repo",
			want:   "https://github.com/test_org/not_test_repo/minty.yaml",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := tc.loader.Source(tc.org, tc.repo)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
		})
	}
}
