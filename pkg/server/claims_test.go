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

package server

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/abcxyz/pkg/testutil"
)

func TestTokenClaim(t *testing.T) {
	t.Parallel()

	token, _ := jwt.NewBuilder().
		Audience([]string{"https://github.com/abcxyz"}).
		Subject("https://token.actions.githubusercontent.com").
		Issuer("repo:abcxyz/test:ref:refs/heads/main").
		Claim("repository", "abcxyz/test").
		Claim("int_claim", 1245).
		Claim("bool_claim", true).
		Build()

	cases := []struct {
		name      string
		token     jwt.Token
		value     string
		required  bool
		want      any
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "success",
			token:     token,
			value:     "repository",
			required:  true,
			want:      "abcxyz/test",
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "missing required",
			token:     token,
			value:     "test",
			required:  true,
			expErr:    true,
			expErrMsg: `claim "test" not found`,
		},
		{
			name:      "missing optional",
			token:     token,
			value:     "test",
			required:  false,
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "success_bool",
			token:     token,
			value:     "bool_claim",
			required:  true,
			want:      true,
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "success_int",
			token:     token,
			value:     "int_claim",
			required:  true,
			want:      1245,
			expErr:    false,
			expErrMsg: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tokenClaim[any](tc.token, tc.value, tc.required)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatal(msg)
			}
		})
	}
}

func TestParsePrivateClaims(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		tokenBuilder *jwt.Builder
		want         *oidcClaims
		expErrMsg    string
	}{
		{
			name: "success-github",
			tokenBuilder: jwt.NewBuilder().
				Audience([]string{"https://github.com/abcxyz"}).
				Subject("repo:abcxyz/test:ref:refs/heads/main").
				Issuer("https://token.actions.githubusercontent.com").
				Claim("repository", "abcxyz/test"),
			want: &oidcClaims{
				Audience:       []string{"https://github.com/abcxyz"},
				Issuer:         "https://token.actions.githubusercontent.com",
				Subject:        "repo:abcxyz/test:ref:refs/heads/main",
				Repository:     "abcxyz/test",
				ParsedOrgName:  "abcxyz",
				ParsedRepoName: "test",
			},
		},
		{
			name: "bad-repo-claim-github",
			tokenBuilder: jwt.NewBuilder().
				Audience([]string{"https://github.com/abcxyz"}).
				Subject("repo:abcxyz/test:ref:refs/heads/main").
				Issuer("https://token.actions.githubusercontent.com").
				Claim("repository", "test"),
			want:      nil,
			expErrMsg: "'repository' claim formatted incorrectly, requires <org_name>/<repo_name> format - received [test]",
		},
		{
			name: "success-google",
			tokenBuilder: jwt.NewBuilder().
				Audience([]string{"https://github.com/abcxyz/test"}).
				Subject("12571298569128659").
				Issuer("https://accounts.google.com").
				Claim("email_verified", true).
				Claim("email", "service-account@project-id.iam.gserviceaccount.com"),
			want: &oidcClaims{
				Audience: []string{"https://github.com/abcxyz/test"},
				Issuer:   "https://accounts.google.com",
				Subject:  "12571298569128659",
				Email:    "service-account@project-id.iam.gserviceaccount.com",
			},
		},
		{
			name: "google-unverified-email",
			tokenBuilder: jwt.NewBuilder().
				Audience([]string{"https://github.com/abcxyz/test"}).
				Subject("12571298569128659").
				Issuer("https://accounts.google.com").
				Claim("email_verified", false).
				Claim("email", "service-account@project-id.iam.gserviceaccount.com"),
			want: &oidcClaims{
				Audience: []string{"https://github.com/abcxyz/test"},
				Issuer:   "https://accounts.google.com",
				Subject:  "12571298569128659",
			},
		},
		{
			name: "google-missing-email-verified",
			tokenBuilder: jwt.NewBuilder().
				Audience([]string{"https://github.com/abcxyz/test"}).
				Subject("12571298569128659").
				Issuer("https://accounts.google.com").
				Claim("email", "service-account@project-id.iam.gserviceaccount.com"),
			want: &oidcClaims{
				Audience: []string{"https://github.com/abcxyz/test"},
				Issuer:   "https://accounts.google.com",
				Subject:  "12571298569128659",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token, err := tc.tokenBuilder.Build()
			if err != nil {
				t.Fatal(err)
			}

			got, err := parsePrivateClaims(token)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatal(msg)
			}
		})
	}
}
