// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/abcxyz/minty/pkg/config"
	"github.com/abcxyz/minty/pkg/permissions"
	"github.com/abcxyz/pkg/logging"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	AUTH_HEADER           = "X-GitHub-OIDC-Token"
	GITHUB_WELL_KNOWN_URL = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
	GITHUB_JWKS_URL       = "https://token.actions.githubusercontent.com/.well-known/jwks"
)

type TokenMintServer interface {
	HandleTokenRequest(w http.ResponseWriter, r *http.Request)
}

type tokenMintServer struct {
	gitHubAppId          string
	gitHubInstallationId string
	gitHubPrivateKey     *rsa.PrivateKey
	configCache          config.ConfigCache
	jwksCache            *jwk.Cache
}

func NewTokenMintServer(ctx context.Context, ghAppId string, ghInstallId string, ghPrivateKey string, configDir string) (TokenMintServer, error) {
	privateKey, err := readPrivateKey(ghPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	cache, err := config.NewMemoryConfigCache(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to build configuration cache: %w", err)
	}
	jwksCache, err := createJWKSCache(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build jwks cache: %w", err)
	}

	return &tokenMintServer{gitHubAppId: ghAppId, gitHubInstallationId: ghInstallId, gitHubPrivateKey: privateKey, configCache: cache, jwksCache: jwksCache}, nil
}

func (s *tokenMintServer) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	s.processRequest(w, r)
	// @TODO - Write call audit data
}

func (s *tokenMintServer) processRequest(w http.ResponseWriter, r *http.Request) {
	logger := logging.FromContext(r.Context())

	// Retrieve the OIDC token from a header.
	oidcHeader := r.Header.Get(AUTH_HEADER)
	// Ensure the token is in the header
	if oidcHeader == "" {
		w.WriteHeader(401)
		fmt.Fprintf(w, "request not authorized: '%s' header is missing", AUTH_HEADER)
		return
	}
	// Parse the token data into a JWT
	oidcToken, err := s.parseJWT(r.Context(), []byte(oidcHeader))
	if err != nil {
		w.WriteHeader(401)
		logger.Errorf("request not authorized: %w", err)
		fmt.Fprintf(w, "request not authorized: '%s' header is invalid", AUTH_HEADER)
		return
	}
	// Extract all of the JWT attributes into a map
	tokenMap, err := oidcToken.AsMap(r.Context())
	if err != nil {
		w.WriteHeader(403)
		logger.Errorf("request header is not a valid jwt: %w", err)
		fmt.Fprintf(w, "request not authorized: '%s' header is invalid", AUTH_HEADER)
		return
	}
	// Find the repository that is making the request
	repo, ok := tokenMap["repository"].(string)
	if !ok {
		w.WriteHeader(500)
		fmt.Fprintf(w, "request does not contain repository information")
		return
	}
	// Get the repository's configuration data
	config, err := s.configCache.ConfigFor(repo)
	if err != nil {
		w.WriteHeader(500)
		logger.Errorf("error reading configuration for repository %s from cache: %w", repo, err)
		fmt.Fprintf(w, "requested repository is not properly configured '%s'", repo)
		return
	}

	// Get the permissions for the token
	perm, err := permissions.GetPermissionsForToken(r.Context(), config, tokenMap)
	if err != nil {
		w.WriteHeader(403)
		logger.Errorf("error evaluating permissions: %w", err)
		fmt.Fprintf(w, "no permissions available")
		return
	}

	// Create a JWT for reading instance information from GitHub
	signedJwt, err := s.generateGitHubAppJWT(tokenMap)
	if err != nil {
		w.WriteHeader(500)
		logger.Errorf("error generating the JWT for GitHub app access: %w", err)
		fmt.Fprintf(w, "error authenticating with GitHub")
	}
	fmt.Printf("JWT: %s\n", string(signedJwt))
	accessToken, err := s.generateInstallationAccessToken(r.Context(), string(signedJwt), tokenMap, perm)
	if err != nil {
		w.WriteHeader(500)
		logger.Errorf("error generating GitHub access token: %w", err)
		fmt.Fprintf(w, "error generating GitHub access token")
	}
	fmt.Fprint(w, string(accessToken))
}

func (s *tokenMintServer) generateInstallationAccessToken(ctx context.Context, ghAppJwt string, tokenMap map[string]interface{}, perm *config.Config) (string, error) {
	logger := logging.FromContext(ctx)

	requestURL := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", s.gitHubInstallationId)
	repository := tokenMap["repository"].(string)
	permissions := perm.Permissions
	request := map[string]interface{}{
		"repository":  repository,
		"permissions": permissions,
	}
	requestJson, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("error marshalling request data: %w", err)
	}
	requestReader := bytes.NewReader(requestJson)
	req, err := http.NewRequest(http.MethodPost, requestURL, requestReader)
	if err != nil {
		return "", fmt.Errorf("error creating http request for GitHub installation information: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ghAppJwt))

	client := http.Client{Timeout: 10 * time.Second}

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making http request for GitHub installation access token %w", err)
	}
	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error reading http response for GitHub installation access token %w", err)
	}
	if res.StatusCode != 200 {
		logger.Errorf("failed to retrieve token from GitHub - Status: %s - Body: %s", res.Status, string(b))
		return "", fmt.Errorf("error generating access token")
	}
	return string(b), nil
}

func (s *tokenMintServer) generateGitHubAppJWT(oidcToken map[string]interface{}) ([]byte, error) {
	iat := time.Now()
	exp := iat.Add(time.Minute * time.Duration(10))
	iss := s.gitHubAppId

	token, err := jwt.NewBuilder().
		Expiration(exp).
		IssuedAt(iat).
		Issuer(iss).
		Build()
	if err != nil {
		return nil, err
	}
	return jwt.Sign(token, jwt.WithKey(jwa.RS256, s.gitHubPrivateKey))
}

func (s *tokenMintServer) parseJWT(ctx context.Context, oidcTokenData []byte) (jwt.Token, error) {
	// Validate the JWT
	logger := logging.FromContext(ctx)
	// Use jwk.Cache if you intend to keep reuse the JWKS over and over
	set, err := s.jwksCache.Get(ctx, GITHUB_JWKS_URL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve jwks information: %w", err)
	}
	var oidcToken jwt.Token
	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		// This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		var rawkey interface{}
		if err := key.Raw(&rawkey); err != nil {
			return nil, fmt.Errorf("failed to create public key from jwks information: %w", err)
		}
		oidcToken, err = jwt.Parse(oidcTokenData, jwt.WithKey(jwa.RS256, rawkey))
		if err == nil {
			return oidcToken, nil
		} else {
			logger.Errorf("oidc token failed to parse: %w", err)
		}
	}
	return nil, fmt.Errorf("oidc token is not valid")
}

func readPrivateKey(privateKeyContent string) (*rsa.PrivateKey, error) {
	privPem, _ := pem.Decode([]byte(privateKeyContent))
	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("error RSA private key is of the wrong type: '%s'", privPem.Type)
	}

	privPemBytes := privPem.Bytes
	var parsedKey interface{}
	// Try a PKCS1 Private Key first
	parsedKey, err := x509.ParsePKCS1PrivateKey(privPemBytes)
	if err != nil {
		// If that fails try a PKCS 8 Private Key
		parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse RSA private key - invalid format: %w", err)
		}

	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unable to parse RSA private key: %w", err)
	}
	return privateKey, nil
}

func createJWKSCache(ctx context.Context) (*jwk.Cache, error) {
	// First, set up the `jwk.Cache` object. You need to pass it a
	// `context.Context` object to control the lifecycle of the background fetching goroutine.
	//
	// Note that by default refreshes only happen very 15 minutes at the
	// earliest. If you need to control this, use `jwk.WithRefreshWindow()`
	c := jwk.NewCache(ctx)

	// Tell *jwk.Cache that we only want to refresh this JWKS
	// when it needs to (based on Cache-Control or Expires header from
	// the HTTP response). If the calculated minimum refresh interval is less
	// than 15 minutes, don't go refreshing any earlier than 15 minutes.
	c.Register(GITHUB_JWKS_URL, jwk.WithMinRefreshInterval(15*time.Minute))

	// Refresh the JWKS once at startup
	_, err := c.Refresh(ctx, GITHUB_JWKS_URL)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh GitHub jwks: %w", err)
	}
	return c, nil
}
