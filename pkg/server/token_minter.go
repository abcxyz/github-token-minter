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

// Package server defines the http request handlers and the route processing
// for this service. The server accepts requests containing OIDC tokens from
// GitHub, validates them against a configuartion and then mints a GitHub application
// token with elevated privlidges.
package server

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/abcxyz/github-token-minter/pkg/version"
	"github.com/abcxyz/pkg/jwtutil"
	"github.com/abcxyz/pkg/logging"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	AuthHeader           = "X-GitHub-OIDC-Token"
	GitHubWellKnowURL    = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
	GitHubJWKSURL        = "https://token.actions.githubusercontent.com/.well-known/jwks"
	GitHubAccessTokenURL = "https://api.github.com/app/installations/%s/access_tokens"
)

type tokenMintServer struct {
	gitHubAppID          string
	gitHubInstallationID string
	gitHubPrivateKey     *rsa.PrivateKey
	configStore          configStore
	verifier             *jwtutil.Verifier
}

// NewRouter creates a new HTTP server implementation that will exchange
// a GitHub OIDC token for a GitHub application token with eleveated privlidges.
func NewRouter(ctx context.Context, ghAppID, ghInstallID, ghPrivateKey, configDir string) (*tokenMintServer, error) {
	privateKey, err := readPrivateKey(ghPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	store, err := newInMemoryStore(configDir)
	if err != nil {
		return nil, fmt.Errorf("failed to build configuration cache: %w", err)
	}
	jwtVerifier, err := jwtutil.NewVerifier(ctx, GitHubJWKSURL)
	if err != nil {
		return nil, fmt.Errorf("failed to build jwt verifier: %w", err)
	}

	return &tokenMintServer{
		gitHubAppID:          ghAppID,
		gitHubInstallationID: ghInstallID,
		gitHubPrivateKey:     privateKey,
		configStore:          store,
		verifier:             jwtVerifier,
	}, nil
}

// handleToken creates a http.HandlerFunc implementation that processes token requests.
func (s *tokenMintServer) handleToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger := logging.FromContext(r.Context())

		respCode, respMsg, err := s.processRequest(r)
		if err != nil {
			logger.Errorw("error processing request", "code", respCode, "body", "erspMsg", "error", err)
		}
		w.WriteHeader(respCode)
		fmt.Fprint(w, respMsg)
	})
}

// handleVersion is a simple http.HandlerFunc that responds
// with version information for the server.
func (s *tokenMintServer) handleVersion() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"version":%q}`, version.HumanVersion)
	})
}

// Routes creates a ServeMux of all of the routes that
// this Router supports.
func (s *tokenMintServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/token", s.handleToken())
	mux.Handle("/version", s.handleVersion())
	return mux
}

func (s *tokenMintServer) processRequest(r *http.Request) (int, string, error) {
	ctx := r.Context()

	// Retrieve the OIDC token from a header.
	oidcHeader := r.Header.Get(AuthHeader)
	// Ensure the token is in the header
	if oidcHeader == "" {
		return http.StatusUnauthorized, fmt.Sprintf("request not authorized: '%s' header is missing", AuthHeader), nil
	}
	// Parse the token data into a JWT
	oidcToken, err := s.verifier.ValidateJWT(oidcHeader)
	if err != nil {
		return http.StatusUnauthorized, fmt.Sprintf("request not authorized: '%s' header is invalid", AuthHeader), err
	}
	// Extract all of the JWT attributes into a map
	tokenMap, err := oidcToken.AsMap(ctx)
	if err != nil {
		return http.StatusUnauthorized, fmt.Sprintf("request not authorized: '%s' jwt is invalid", AuthHeader), err
	}
	// Find the repository that is making the request
	repo, ok := tokenMap["repository"].(string)
	if !ok {
		return http.BadRequest, "request does not contain repository information", nil
	}
	// Get the repository's configuration data
	config, err := s.configStore.ConfigFor(repo)
	if err != nil {
		return http.StatusInternalServerError,
			fmt.Sprintf("requested repository is not properly configured '%s'", repo),
			fmt.Errorf("error reading configuration for repository %s from cache: %w", repo, err)
	}

	// Get the permissions for the token
	perm, err := permissionsForToken(ctx, config, tokenMap)
	if err != nil {
		return http.StatusForbidden, "no permissions available", err
	}

	// Create a JWT for reading instance information from GitHub
	signedJwt, err := s.generateGitHubAppJWT(tokenMap)
	if err != nil {
		return http.StatusInternalServerError,
			"error authenticating with GitHub",
			fmt.Errorf("error generating the JWT for GitHub app access: %w", err)
	}
	accessToken, err := s.generateInstallationAccessToken(ctx, string(signedJwt), tokenMap, perm)
	if err != nil {
		return http.StatusInternalServerError, "error generating GitHub access token", err
	}
	return http.StatusOK, accessToken, nil
}

// generateInstallationAccessToken makes a call to the GitHub API to generate a new
// application level access token.
func (s *tokenMintServer) generateInstallationAccessToken(ctx context.Context, ghAppJwt string, tokenMap map[string]interface{}, perm *config) (string, error) {
	logger := logging.FromContext(ctx)

	requestURL := fmt.Sprintf(GitHubAccessTokenURL, s.gitHubInstallationID)
	repository, ok := tokenMap["repository"].(string)
	if !ok {
		return "", fmt.Errorf("error reading repository information")
	}
	permissions := perm.Permissions
	request := map[string]interface{}{
		"repository":  repository,
		"permissions": permissions,
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("error marshalling request data: %w", err)
	}
	requestReader := bytes.NewReader(requestJSON)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, requestReader)
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

	b, err := io.ReadAll(io.LimitReader(res.Body, 64_000))
	if err != nil {
		return "", fmt.Errorf("error reading http response for GitHub installation access token %w", err)
	}

	if res.StatusCode != http.StatusOK {
		logger.Errorf("failed to retrieve token from GitHub - Status: %s - Body: %s", res.Status, string(b))
		return "", fmt.Errorf("error generating access token")
	}

	return string(b), nil
}

// generateGitHubAppJWT creates a signed JWT to authenticate this service as a
// GitHub app that can make API calls to GitHub.
func (s *tokenMintServer) generateGitHubAppJWT(oidcToken map[string]interface{}) ([]byte, error) {
	iat := time.Now()
	exp := iat.Add(10 * time.Minute)
	iss := s.gitHubAppID

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

func readPrivateKey(privateKeyContent string) (*rsa.PrivateKey, error) {
	parsedKey, _, err := jwk.DecodePEM([]byte(privateKeyContent))
	if err != nil {
		return nil, err
	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unable to parse RSA private key: %w", err)
	}
	return privateKey, nil
}
