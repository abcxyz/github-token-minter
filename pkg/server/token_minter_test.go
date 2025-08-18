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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/github-token-minter/pkg/server/source"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/testutil"
)

func handleAccessTokenRequest(w http.ResponseWriter, r *http.Request) {
	// Parse the request information
	defer r.Body.Close()

	var request tokenRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4_194_304)) // 4 MiB
	if err := dec.Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "error parsing request information - invalid JSON: %s", err)
		return
	}
	perms := make([]string, 0, len(request.Permissions))
	for k, v := range request.Permissions {
		perms = append(perms, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(perms)

	w.WriteHeader(201)
	fmt.Fprintf(w, `{"token": "%s"}`, perms)
}

func TestTokenMintServer_ProcessRequest(t *testing.T) {
	t.Parallel()

	ctx := logging.WithLogger(t.Context(), logging.TestLogger(t))

	jwksServer, signer := testJwksServer(t)

	jwkCache := jwk.NewCache(ctx)
	if err := jwkCache.Register(jwksServer.URL); err != nil {
		t.Fatal(err)
	}
	jwkCachedSet := jwk.NewCachedSet(jwkCache, jwksServer.URL)
	jwtParseOptions := []jwt.ParseOption{
		jwt.WithKeySet(jwkCachedSet, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithAcceptableSkew(5 * time.Second),
	}

	fakeGitHub := func() *httptest.Server {
		mux := http.NewServeMux()
		mux.Handle("GET /orgs/abcxyz/installation", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"access_tokens_url": "http://%s/app/installations/123/access_tokens"}`, r.Host)
		}))
		mux.Handle("POST /app/installations/123/access_tokens", http.HandlerFunc(handleAccessTokenRequest))

		mux.Handle("GET /orgs/org1/installation", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"access_tokens_url": "http://%s/app/installations/456/access_tokens"}`, r.Host)
		}))
		mux.Handle("POST /app/installations/456/access_tokens", http.HandlerFunc(handleAccessTokenRequest))
		mux.Handle("GET /api/v3/repos/org1/pkg/contents/.github/minty.yaml", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Page not found", http.StatusNotFound)
		}))
		mux.Handle("GET /api/v3/repos/org1/.minty/contents/minty.yaml", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, err := os.ReadFile("../../testdata/configs/org1/minty.yaml")
			if err != nil {
				http.Error(w, "Failed to load config file", http.StatusInternalServerError)
				return
			}
			content := base64.StdEncoding.EncodeToString(data)
			fmt.Fprintf(w, `{"encoding": "base64","type":"file","content": "%s"}`, content)
		}))
		// mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 	w.WriteHeader(http.StatusForbidden)
		// })

		return httptest.NewServer(mux)
	}()
	t.Cleanup(func() {
		fakeGitHub.Close()
	})

	cases := []struct {
		name     string
		req      *http.Request
		expCode  int
		expResp  string
		expErr   string
		resolver mockJwksResolver
	}{
		{
			name: "no_token_header",
			req: func() *http.Request {
				return httptest.NewRequest("GET", "/", nil).WithContext(ctx)
			}(),
			expCode: 400,
			expResp: "header is missing",
		},
		{
			name: "invalid_body",
			req: func() *http.Request {
				body := strings.NewReader(`totally not valid`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)
				r.Header.Set("X-OIDC-Token", "abc123")
				return r
			}(),
			expCode: 400,
			expResp: "invalid JSON",
			expErr:  "error parsing request",
		},
		{
			name: "invalid_jwt",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)
				r.Header.Set("X-OIDC-Token", "abc123")
				return r
			}(),
			expCode: 401,
			expResp: "header is invalid",
			expErr:  "failed to validate jwt",
		},
		{
			name: "missing_repository_github",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 400,
			expResp: "request does not contain required information",
			expErr:  `claim "repository" not found`,
		},
		{
			name: "missing_repository_non_github",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GoogleIssuer)
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 400,
			expResp: "request does not contain required information",
			expErr:  `non-github OIDC token's audience field should have exactly one entry of a repository containing a minty config`,
		},
		{
			name: "failed_to_resolve_keyset",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				err: errors.New("could not resolve key set"),
			},
			expCode: 401,
			expResp: "request not authorized: could not resolve JWK keys",
			expErr:  "failed to validate jwt",
		},
		{
			name: "happy_path_github",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[issues=read]",
		},
		{
			name: "happy_path_non_github",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GoogleIssuer)
					b.Audience([]string{"abcxyz/pkg"})
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
					b.Claim("email", "service-account-email@project-id.iam.gserviceaccount.com")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[issues=read]",
		},
		{
			name: "request_with_permissions",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test-perms","permissions":{"contents":"write"}}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[contents=write]",
		},
		{
			name: "request_with_no_permissions",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test-perms"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[contents=write issues=read]",
		},
		{
			name: "request_with_matching_permissions",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test-perms","permissions":{"contents":"write","issues":"read"}}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[contents=write issues=read]",
		},
		{
			name: "happy_path_no_repositories_in_request",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[issues=read]",
		},
		{
			name: "happy_path_empty_repositories_in_request",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test", "repositories":[]}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[issues=read]",
		},
		{
			name: "happy_path_cross_org_single_repo_in_request",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"cross_org_test", "repositories":["repoA"], "org_name":"org1"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[issues=read]",
		},
		{
			name: "happy_path_cross_org_multi_repo_in_request",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"cross_org_test", "repositories":["repoA", "repoB"], "org_name":"org1"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[issues=read]",
		},
		{
			name: "happy_path_same_org_all_repositories",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test", "repositories":["*"]}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[issues=read]",
		},
		{
			name: "happy_path_cross_org_all_repositories",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"minty_cross_org", "repositories":["*"], "org_name":"org1"}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "[contents=write]",
		},
		{
			name: "unhappy_path_mixing_all_and_specific_repos",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test", "repositories":["*", "pkg"]}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/pkg")
					b.Claim("workflow_ref", "abcxyz/pkg/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 403,
			expResp: "request for '*' also contained request for specific repositories and that is not allowed",
		},
		{
			name: "unhappy_path_all_repos_no_config",
			req: func() *http.Request {
				body := strings.NewReader(`{"scope":"test", "repositories":["*"]}`)
				r := httptest.NewRequest("GET", "/", body).WithContext(ctx)

				signed := testTokenBuilder(t, signer, func(b *jwt.Builder) {
					b.Issuer(config.GitHubIssuer)
					b.Claim("repository", "abcxyz/no-config-repo")
					b.Claim("workflow_ref", "abcxyz/no-config-repo/.github/workflows/test.yml")
				})
				r.Header.Set("X-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 500,
			expResp: "requested scope \"test\" is not found for repository \"abcxyz\"/\"no-config-repo\"",
			expErr:  "error reading configuration for repository abcxyz/no-config-repo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}

			ghAppCfg := &source.GitHubAppConfig{
				AppID:  "app-id",
				Signer: rsaPrivateKey,
			}

			sourceSystem, err := source.NewGitHubSourceSystem(ctx, []*source.GitHubAppConfig{ghAppCfg}, fakeGitHub.URL)
			if err != nil {
				t.Fatal(err)
			}

			configStore, err := config.NewConfigEvaluator(1*time.Hour, "../../testdata/configs", ".github/minty.yaml", ".minty", "minty.yaml", "main", sourceSystem)
			if err != nil {
				t.Fatal(err)
			}

			server, err := NewRouter(ctx, sourceSystem, configStore, &JWTParser{ParseOptions: jwtParseOptions, jwkResolver: &tc.resolver})
			if err != nil {
				t.Fatal(err)
			}

			resp := server.processRequest(tc.req)
			if got, want := resp.Code, tc.expCode; got != want {
				t.Errorf("expected status code %d to be %d", got, want)
			}
			if got, want := resp.Message, tc.expResp; !strings.Contains(got, want) {
				t.Errorf("expected body\n\n%s\n\nto contain\n\n%s\n\n", got, want)
			}
			if diff := testutil.DiffErrString(resp.Error, tc.expErr); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestValidateRepositories(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		allow     []string
		request   []string
		want      []string
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "empty allow single request",
			allow:     []string{},
			request:   []string{"test1"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "test1" is not in the allow list`,
		},
		{
			name:      "single allow single request - match",
			allow:     []string{"test1"},
			request:   []string{"test1"},
			want:      []string{"test1"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow single request - match",
			allow:     []string{"test1", "test2"},
			request:   []string{"test1"},
			want:      []string{"test1"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow multiple request - match",
			allow:     []string{"test1", "test2"},
			request:   []string{"test1", "test2"},
			want:      []string{"test1", "test2"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow multiple request - not first - match",
			allow:     []string{"test1", "test2", "test3", "test4"},
			request:   []string{"test4", "test2"},
			want:      []string{"test4", "test2"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "single allow single request - no match",
			allow:     []string{"test1"},
			request:   []string{"test2"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "test2" is not in the allow list`,
		},
		{
			name:      "multiple allow single request - no match",
			allow:     []string{"test1", "test2", "test3"},
			request:   []string{"test4"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "test4" is not in the allow list`,
		},
		{
			name:      "multiple allow multiple request - no match",
			allow:     []string{"test1", "test2", "test3"},
			request:   []string{"test4", "test5"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "test4" is not in the allow list`,
		},
		{
			name:      "single allow * request - match",
			allow:     []string{"test1", "test2", "test3"},
			request:   []string{"*"},
			want:      []string{"test1", "test2", "test3"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "empty allow * request",
			allow:     []string{},
			request:   []string{"*"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "*" is not in the allow list`,
		},
		{
			name:      "empty allow prefix-* request",
			allow:     []string{},
			request:   []string{"prefix-*"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "prefix-*" is not in the allow list`,
		},
		{
			name:      "single allow prefix-* request - match",
			allow:     []string{"test1"},
			request:   []string{"test*"},
			want:      []string{"test1"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow prefix-* request - all match",
			allow:     []string{"test1", "test2"},
			request:   []string{"test*"},
			want:      []string{"test1", "test2"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow prefix-* request - partial match",
			allow:     []string{"test1", "test2", "nottest"},
			request:   []string{"test*"},
			want:      []string{"test1", "test2"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "single allow prefix-* request - no match",
			allow:     []string{"test1"},
			request:   []string{"prefix-*"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "prefix-*" is not in the allow list`,
		},
		{
			name:      "multiple allow prefix-* request - no match",
			allow:     []string{"test1", "test2"},
			request:   []string{"prefix-*"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "prefix-*" is not in the allow list`,
		},
		{
			name:      "allow all",
			allow:     []string{"*"},
			request:   []string{"test1", "test2"},
			want:      []string{"test1", "test2"},
			expErr:    false,
			expErrMsg: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := validateRepositories(tc.allow, tc.request)
			if diff := cmp.Diff(tc.want, got); diff != "" {
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

func TestIsRequestAllRepos(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		allow   []string
		request []string
		want    bool
	}{
		{
			name:    "allow all repos",
			allow:   []string{"*"},
			request: []string{"*"},
			want:    true,
		},
		{
			name:    "disallow all repos",
			allow:   []string{"test1"},
			request: []string{"*"},
			want:    false,
		},
		{
			name:    "allow all only with * request",
			allow:   []string{"*"},
			request: []string{"test1"},
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := isRequestAllRepos(tc.allow, tc.request)
			if got != tc.want {
				t.Errorf("allowRequestAllRepos got=%t, want=%t", got, tc.want)
			}
		})
	}
}

func testJwksServer(tb testing.TB) (*httptest.Server, crypto.Signer) {
	tb.Helper()

	// Setup jwks server
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	keyID := "test-kid"
	ecdsaKey, err := jwk.FromRaw(privateKey.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	if err := ecdsaKey.Set(jwk.KeyIDKey, keyID); err != nil {
		tb.Fatal(err)
	}
	jwks := make(map[string][]jwk.Key)
	jwks["keys"] = []jwk.Key{ecdsaKey}

	j, err := json.Marshal(jwks)
	if err != nil {
		tb.Fatal("couldn't create jwks json")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s", j)
	})

	srv := httptest.NewServer(mux)
	tb.Cleanup(func() { srv.Close() })

	return srv, privateKey
}

func testTokenBuilder(tb testing.TB, signer crypto.Signer, fn func(*jwt.Builder)) string {
	tb.Helper()

	b := jwt.NewBuilder()
	if fn != nil {
		fn(b)
	}
	token, err := b.Build()
	if err != nil {
		tb.Fatal(err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, "test-kid"); err != nil {
		tb.Fatal(err)
	}

	signed, err := jwt.Sign(token,
		jwt.WithKey(jwa.ES256, signer, jws.WithProtectedHeaders(headers)))
	if err != nil {
		tb.Fatal(err)
	}
	return string(signed)
}

type mockJwksResolver struct {
	keySet jwk.Set
	err    error
}

func (r *mockJwksResolver) ResolveKeySet(ctx context.Context, oidcHeader string) (jwk.Set, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.keySet, nil
}
