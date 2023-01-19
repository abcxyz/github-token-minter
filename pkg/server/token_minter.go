// Copyright 2023 The Authors (see AUTHORS file)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package server defines the http request handlers and the route processing
// for this service. The server accepts requests containing OIDC tokens from
// GitHub, validates them against a configuration and then mints a GitHub application
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
	"github.com/abcxyz/pkg/cache"
	"github.com/abcxyz/pkg/jwtutil"
	"github.com/abcxyz/pkg/logging"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	AuthHeader  = "X-GitHub-OIDC-Token"
	JWTCacheKey = "github-app-jwt"
)

// TokenMintServer is the implementation of an HTTP server that exchanges
// a GitHub OIDC token for a GitHub application token with eleveated privlidges.
type TokenMintServer struct {
	gitHubAppConfig GitHubAppConfig
	configStore     ConfigReader
	verifier        *jwtutil.Verifier
	jwtCache        *cache.Cache[[]byte]
	messenger       *PubSubMessenger
}

// GitHubAppConfig contains all of the required configuration informaion for
// operating as a GitHub App.
type GitHubAppConfig struct {
	AppID          string
	InstallationID string
	PrivateKey     *rsa.PrivateKey
	AccessTokenURL string
}

type requestPayload struct {
	Repositories map[string]string `json:"repositories"`
	Permissions  map[string]string `json:"permissions"`
}

type oidcClaims struct {
	Audience          []string
	Subject           string
	Issuer            string
	Ref               string
	RefType           string
	Sha               string
	Repository        string
	RepositoryID      string
	RepositoryOwner   string
	RepositoryOwnerID string
	RunID             string
	RunNumber         string
	Actor             string
	ActorID           string
	EventName         string
	Workflow          string
	WorkflowRef       string
	WorkflowSha       string
	JobWorkflowRef    string
	JobWorkflowSha    string
}

type auditEvent struct {
	ID               string            `json:"id"`
	Received         time.Time         `json:"received"`
	HTTPStatusCode   int               `json:"http_status_code"`
	HTTPErrorMessage string            `json:"http_error_msg"`
	Token            *oidcClaims       `json:"oidc_token_claims"`
	Request          *requestPayload   `json:"request"`
	Config           *RepositoryConfig `json:"repository_config"`
}

// NewRouter creates a new HTTP server implementation that will exchange
// a GitHub OIDC token for a GitHub application token with eleveated privlidges.
func NewRouter(ctx context.Context, ghAppConfig GitHubAppConfig, configStore ConfigReader, jwtVerifier *jwtutil.Verifier, messenger *PubSubMessenger) (*TokenMintServer, error) {
	return &TokenMintServer{
		gitHubAppConfig: ghAppConfig,
		configStore:     configStore,
		verifier:        jwtVerifier,
		// Tokens expire in 10 minutes. Storing it for 9 minutes ensures that it is evicted from the cache
		// before it expires.
		jwtCache:  cache.New[[]byte](9 * time.Minute),
		messenger: messenger,
	}, nil
}

// handleToken creates a http.HandlerFunc implementation that processes token requests.
func (s *TokenMintServer) handleToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := logging.FromContext(ctx)

		auditEvent := auditEvent{
			Received: time.Now().UTC(),
		}

		respCode, respMsg, err := s.processRequest(r, &auditEvent)
		if err != nil {
			auditEvent.HTTPErrorMessage = err.Error()
			logger.Errorw("error processing request", "code", respCode, "body", respMsg, "error", err)
		}
		auditEvent.HTTPStatusCode = respCode

		// Marshal the audit event and post it to pubsub.
		eventBytes, err := json.Marshal(&auditEvent)
		if err != nil {
			logger.Errorw("failed to marshal event json", "error", err)
		}
		if err := s.messenger.Send(ctx, eventBytes); err != nil {
			logger.Errorw("failed to send audit event to pubsub", "error", err)
		}

		w.WriteHeader(respCode)
		fmt.Fprint(w, respMsg)
	})
}

// handleVersion is a simple http.HandlerFunc that responds
// with version information for the server.
func (s *TokenMintServer) handleVersion() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"version":%q}\n`, version.HumanVersion)
	})
}

// Routes creates a ServeMux of all of the routes that
// this Router supports.
func (s *TokenMintServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/token", s.handleToken())
	mux.Handle("/version", s.handleVersion())
	return mux
}

func (s *TokenMintServer) processRequest(r *http.Request, auditEvent *auditEvent) (int, string, error) {
	ctx := r.Context()

	// Retrieve the OIDC token from a header.
	oidcHeader := r.Header.Get(AuthHeader)
	// Ensure the token is in the header
	if oidcHeader == "" {
		return http.StatusBadRequest, fmt.Sprintf("request not authorized: '%s' header is missing", AuthHeader), nil
	}

	// Parse the request information
	defer r.Body.Close()

	var request requestPayload
	dec := json.NewDecoder(io.LimitReader(r.Body, 64_000))
	if err := dec.Decode(&request); err != nil {
		return http.StatusBadRequest, "error parsing request information - invalid JSON", fmt.Errorf("error parsing request: %w", err)
	}
	auditEvent.Request = &request

	// Parse the token data into a JWT
	oidcToken, err := s.verifier.ValidateJWT(oidcHeader)
	if err != nil {
		return http.StatusUnauthorized, fmt.Sprintf("request not authorized: '%s' header is invalid", AuthHeader), err
	}

	claims, err := parsePrivateClaims(ctx, oidcToken)
	if err != nil {
		return http.StatusBadRequest, "request does not contain required information", err
	}
	auditEvent.Token = claims
	// Get the repository's configuration data
	config, err := s.configStore.Read(claims.Repository)
	if err != nil {
		return http.StatusInternalServerError,
			fmt.Sprintf("requested repository is not properly configured '%s'", claims.Repository),
			fmt.Errorf("error reading configuration for repository %s from cache: %w", claims.Repository, err)
	}
	auditEvent.Config = config

	// Extract all of the JWT attributes into a map
	tokenMap, err := oidcToken.AsMap(ctx)
	if err != nil {
		return http.StatusInternalServerError, fmt.Sprintf("request not authorized: '%s' jwt is invalid", AuthHeader), err
	}
	// Get the permissions for the token
	perm, err := permissionsForToken(ctx, config, tokenMap)
	if err != nil {
		return http.StatusForbidden, "no permissions available for repository", err
	}

	// Validate the permissions that were requested are within what is allowed for the repository
	if err = validatePermissions(ctx, perm.Permissions, request.Permissions); err != nil {
		return http.StatusForbidden, "requested permissions are not authorized for this repository", err
	}

	// Check for a valid JWT in the cache
	signedJwt, ok := s.jwtCache.Lookup(JWTCacheKey)
	if !ok {
		// Create a JWT for reading instance information from GitHub
		signedJwt, err = s.generateGitHubAppJWT()
		if err != nil {
			return http.StatusInternalServerError,
				"error authenticating with GitHub",
				fmt.Errorf("error generating the JWT for GitHub app access: %w", err)
		}
		s.jwtCache.Set(JWTCacheKey, signedJwt)
	}
	accessToken, err := s.generateInstallationAccessToken(ctx, string(signedJwt), tokenMap, perm)
	if err != nil {
		return http.StatusInternalServerError, "error generating GitHub access token", err
	}
	return http.StatusOK, accessToken, nil
}

// generateInstallationAccessToken makes a call to the GitHub API to generate a new
// application level access token.
func (s *TokenMintServer) generateInstallationAccessToken(ctx context.Context, ghAppJwt string, tokenMap map[string]interface{}, perm *Config) (string, error) {
	logger := logging.FromContext(ctx)

	requestURL := fmt.Sprintf(s.gitHubAppConfig.AccessTokenURL, s.gitHubAppConfig.InstallationID)
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

	if res.StatusCode != http.StatusCreated {
		logger.Errorf("failed to retrieve token from GitHub - Status: %s - Body: %s", res.Status, string(b))
		return "", fmt.Errorf("error generating access token")
	}

	return string(b), nil
}

// generateGitHubAppJWT creates a signed JWT to authenticate this service as a
// GitHub app that can make API calls to GitHub.
func (s *TokenMintServer) generateGitHubAppJWT() ([]byte, error) {
	iat := time.Now()
	exp := iat.Add(10 * time.Minute)
	iss := s.gitHubAppConfig.AppID

	token, err := jwt.NewBuilder().
		Expiration(exp).
		IssuedAt(iat).
		Issuer(iss).
		Build()
	if err != nil {
		return nil, fmt.Errorf("error building JWT: %w", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, s.gitHubAppConfig.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("error signing JWT: %w", err)
	}
	return signed, nil
}

// parsePrivateClaims extracts the private claims from the OIDC token into an internal
// representation and validates that all required claims are present.
func parsePrivateClaims(ctx context.Context, oidcToken jwt.Token) (*oidcClaims, error) {
	var claims oidcClaims

	claims.Audience = oidcToken.Audience()
	claims.Subject = oidcToken.Subject()
	claims.Issuer = oidcToken.Issuer()

	r, err := requiredClaim(oidcToken, "repository")
	if err != nil {
		return nil, err
	}
	claims.Repository = r

	claims.Ref = optionalClaim(oidcToken, "ref")
	claims.RefType = optionalClaim(oidcToken, "ref_type")
	claims.Sha = optionalClaim(oidcToken, "sha")
	claims.RepositoryID = optionalClaim(oidcToken, "repository_id")
	claims.RepositoryOwner = optionalClaim(oidcToken, "repository_owner")
	claims.RepositoryOwnerID = optionalClaim(oidcToken, "repository_owner_id")
	claims.RunID = optionalClaim(oidcToken, "run_id")
	claims.RunNumber = optionalClaim(oidcToken, "run_number")
	claims.Actor = optionalClaim(oidcToken, "actor")
	claims.ActorID = optionalClaim(oidcToken, "actor_id")
	claims.EventName = optionalClaim(oidcToken, "event_name")
	claims.Workflow = optionalClaim(oidcToken, "workflow")
	claims.WorkflowRef = optionalClaim(oidcToken, "workflow_ref")
	claims.WorkflowSha = optionalClaim(oidcToken, "workflow_sha")
	claims.JobWorkflowRef = optionalClaim(oidcToken, "job_workflow_ref")
	claims.JobWorkflowSha = optionalClaim(oidcToken, "job_workflow_sha")

	return &claims, nil
}

func requiredClaim(oidcToken jwt.Token, claim string) (string, error) {
	return tokenClaimString(oidcToken, claim, true)
}

func optionalClaim(oidcToken jwt.Token, claim string) string {
	// Intentionally dropping the error here since the existence of the claim does not matter
	result, _ := tokenClaimString(oidcToken, claim, false)
	return result
}

func tokenClaimString(oidcToken jwt.Token, claim string, required bool) (string, error) {
	val, ok := oidcToken.Get(claim)
	if required && !ok {
		return "", fmt.Errorf("required claim %q not found", claim)
	}
	result, ok := val.(string)
	if required && !ok {
		return "", fmt.Errorf("required claim %q not the correct type want=string, got=%t", claim, val)
	}
	return result, nil
}
