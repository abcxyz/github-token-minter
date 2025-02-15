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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/testutil"
)

func TestJWKResolver(t *testing.T) {
	t.Parallel()

	ctx := logging.WithLogger(t.Context(), logging.TestLogger(t))

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	allowlist := []string{config.GitHubIssuer, config.GoogleIssuer, "https://fakeurlthatdoesnotexist.com"}
	resolver := NewOIDCResolver(ctx, allowlist, time.Hour*4)

	cases := []struct {
		name   string
		issuer string
		expErr string
	}{
		{
			name:   "github",
			issuer: config.GitHubIssuer,
		},
		{
			name:   "google",
			issuer: config.GoogleIssuer,
		},
		{
			name:   "not-allowed-issuer",
			issuer: "https://issuernotinallowlist.com",
			expErr: "is not allowlisted",
		},
		{
			name:   "bad-issuer",
			issuer: "https://fakeurlthatdoesnotexist.com",
			expErr: "error fetching OpenID Configuration",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tokenString := testTokenBuilder(t, signer, func(b *jwt.Builder) {
				b.Issuer(tc.issuer)
			})

			keySet, err := resolver.ResolveKeySet(ctx, tokenString)

			if diff := testutil.DiffErrString(err, tc.expErr); diff != "" {
				t.Error(diff)
			}

			if tc.expErr == "" && keySet.Len() == 0 {
				t.Errorf("key set should not be empty for real issuer %q", tc.issuer)
			}
		})
	}
}
