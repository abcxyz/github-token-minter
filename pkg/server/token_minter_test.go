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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/pkg/githubauth"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/testutil"
)

func TestTokenMintServer_ProcessRequest(t *testing.T) {
	t.Parallel()

	ctx := logging.WithLogger(context.Background(), logging.TestLogger(t))

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
		mux.Handle("GET /repos/abcxyz/pkg/installation", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"access_tokens_url": "http://%s/app/installations/123/access_tokens"}`, r.Host)
		}))
		mux.Handle("POST /app/installations/123/access_tokens", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"token": "this-is-the-token-from-github"}`)
		}))

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
				r.Header.Set("X-GitHub-OIDC-Token", "abc123")
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
				r.Header.Set("X-GitHub-OIDC-Token", "abc123")
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
				r.Header.Set("X-GitHub-OIDC-Token", signed)
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
				r.Header.Set("X-GitHub-OIDC-Token", signed)
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
				r.Header.Set("X-GitHub-OIDC-Token", signed)
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
				r.Header.Set("X-GitHub-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "this-is-the-token-from-github",
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
				})
				r.Header.Set("X-GitHub-OIDC-Token", signed)
				return r
			}(),
			resolver: mockJwksResolver{
				keySet: jwkCachedSet,
			},
			expCode: 200,
			expResp: "this-is-the-token-from-github",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}

			githubApp, err := githubauth.NewApp("app-id", rsaPrivateKey, githubauth.WithBaseURL(fakeGitHub.URL))
			if err != nil {
				t.Fatal(err)
			}
			configStore, err := config.NewConfigEvaluator(1*time.Hour, "../../testdata/configs", ".github/minty.yaml", ".google-github", "minty.yaml", "main", githubApp)
			if err != nil {
				t.Fatal(err)
			}

			server, err := NewRouter(ctx, githubApp, configStore, &JWTParser{ParseOptions: jwtParseOptions, jwkResolver: &tc.resolver})
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
				t.Errorf(diff)
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
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := validateRepositories(tc.allow, tc.request)
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

func TestAllowRequestAllRepos(t *testing.T) {
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
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := allowRequestAllRepos(tc.allow, tc.request)
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
