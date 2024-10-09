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

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type JWKResolver interface {
	ResolveKeySet(ctx context.Context, oidcHeader string) (jwk.Set, error)
}

type OIDCResolver struct {
	cache           *jwk.Cache
	issuerToJwksURI map[string]string
}

type OpenIDConfiguration struct {
	// The only field we need from the config
	JwksURI string `json:"jwks_uri"`
}

func NewOIDCResolver(ctx context.Context) *OIDCResolver {
	return &OIDCResolver{
		cache:           jwk.NewCache(ctx),
		issuerToJwksURI: map[string]string{},
	}
}

func (r *OIDCResolver) ResolveKeySet(ctx context.Context, oidcHeader string) (jwk.Set, error) {
	issuer, err := r.extractIssuer(ctx, oidcHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuer from token: %w", err)
	}

	err = r.registerIssuer(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to register issuer %q: %w", issuer, err)
	}

	return jwk.NewCachedSet(r.cache, r.issuerToJwksURI[issuer]), nil
}

func (r *OIDCResolver) extractIssuer(ctx context.Context, oidcHeader string) (string, error) {
	// Parse without validation to extract issuer so we can use it to obtain the key set to use for validation
	token, err := jwt.ParseString(oidcHeader, jwt.WithContext(ctx), jwt.WithVerify(false))
	if err != nil {
		return "", fmt.Errorf("failed to parse jwt header: %w", err)
	}
	return token.Issuer(), nil
}

func (r *OIDCResolver) registerIssuer(issuer string) error {
	jwksURI, err := r.resolveJwksURI(issuer)
	if err != nil {
		return fmt.Errorf("failed to resolve JWKS URI for %q: %w", issuer, err)
	}

	if !r.cache.IsRegistered(jwksURI) {
		err = r.cache.Register(jwksURI)
		if err != nil {
			return fmt.Errorf("failed to register JWKS URI %q to cache: %w", jwksURI, err)
		}
	}

	return nil
}

func (r *OIDCResolver) resolveJwksURI(issuer string) (string, error) {
	uri, cached := r.issuerToJwksURI[issuer]
	if cached {
		return uri, nil
	}

	configURL, err := url.JoinPath(issuer, ".well-known", "openid-configuration")
	if err != nil {
		return "", fmt.Errorf("error processing issuer URL %q: %w", issuer, err)
	}

	resp, err := http.Get(configURL)
	if err != nil {
		return "", fmt.Errorf("error fetching OpenID Configuration from %q: %w", configURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body from GET %q: %w", configURL, err)
	}

	var config OpenIDConfiguration
	err = json.Unmarshal(body, &config)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal OpenID Configuration: %w", err)
	}

	r.issuerToJwksURI[issuer] = config.JwksURI

	return config.JwksURI, nil
}
