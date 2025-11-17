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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/abcxyz/pkg/cache"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JWKResolver interface {
	ResolveKeySet(ctx context.Context, oidcHeader string) (jwk.Set, error)
}

type OIDCResolver struct {
	issuerAllowlist []string
	cache           *cache.Cache[jwk.Set]
}

type OpenIDConfiguration struct {
	// The only field we need from the config
	JwksURI string `json:"jwks_uri"`
}

func NewOIDCResolver(ctx context.Context, issuerAllowlist []string, cacheTimeout time.Duration) *OIDCResolver {
	return &OIDCResolver{
		issuerAllowlist: issuerAllowlist,
		cache:           cache.New[jwk.Set](cacheTimeout),
	}
}

// ResolveKeySet finds and caches the correct OIDC key set to use based on the token's issuer's OpenID Configuration.
func (r *OIDCResolver) ResolveKeySet(ctx context.Context, oidcHeader string) (jwk.Set, error) {
	// Parse without verification to extract issuer so we can use it to obtain the key set to use for verification
	token, err := jwt.ParseString(oidcHeader, jwt.WithContext(ctx), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer from jwt header: %w", err)
	}
	issuer := token.Issuer()

	if !slices.Contains(r.issuerAllowlist, issuer) {
		return nil, fmt.Errorf("issuer %q is not allowlisted", issuer)
	}

	keySet, err := r.cache.WriteThruLookup(issuer, func() (jwk.Set, error) {
		jwksURI, err := r.resolveJwksURI(ctx, issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve JWKS URI for %q: %w", issuer, err)
		}
		keySet, err := jwk.Fetch(ctx, jwksURI)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS for %q: %w", issuer, err)
		}
		return keySet, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve key set: %w", err)
	}

	return keySet, nil
}

func (r *OIDCResolver) resolveJwksURI(ctx context.Context, issuer string) (string, error) {
	configURL, err := url.JoinPath(issuer, ".well-known", "openid-configuration")
	if err != nil {
		return "", fmt.Errorf("error processing issuer URL %q: %w", issuer, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating GET request for %q: %w", configURL, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error fetching OpenID Configuration from %q: %w", configURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 25_165_824)) // 24 MiB
	if err != nil {
		return "", fmt.Errorf("failed to read response body from GET %q: %w", configURL, err)
	}

	var config OpenIDConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return "", fmt.Errorf("failed to unmarshal OpenID Configuration: %w", err)
	}

	return config.JwksURI, nil
}
