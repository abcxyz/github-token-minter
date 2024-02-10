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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/genproto/googleapis/cloud/audit"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/abcxyz/github-token-minter/pkg/version"
	api "github.com/abcxyz/lumberjack/clients/go/apis/v1alpha1"
	lumberjack "github.com/abcxyz/lumberjack/clients/go/pkg/audit"
	"github.com/abcxyz/pkg/githubauth"
	"github.com/abcxyz/pkg/logging"
)

const (
	AuthHeader  = "X-GitHub-OIDC-Token"
	JWTCacheKey = "github-app-jwt"
)

// TokenMintServer is the implementation of an HTTP server that exchanges
// a GitHub OIDC token for a GitHub application token with eleveated privlidges.
type TokenMintServer struct {
	githubApp        *githubauth.App
	configStore      ConfigReader
	jwtParseOptions  []jwt.ParseOption
	lumberjackClient *lumberjack.Client
}

type oidcClaims struct {
	Audience          []string `json:"audience"`
	Subject           string   `json:"subject"`
	Issuer            string   `json:"issuer"`
	Ref               string   `json:"ref"`
	RefType           string   `json:"ref_type"`
	Sha               string   `json:"sha"`
	Repository        string   `json:"repository"`
	RepositoryID      string   `json:"repository_id"`
	RepositoryOwner   string   `json:"repository_owner"`
	RepositoryOwnerID string   `json:"repository_owner_id"`
	RunID             string   `json:"run_id"`
	RunNumber         string   `json:"run_number"`
	Actor             string   `json:"actor"`
	ActorID           string   `json:"actor_id"`
	EventName         string   `json:"event_name"`
	Workflow          string   `json:"workflow"`
	WorkflowRef       string   `json:"workflow_ref"`
	WorkflowSha       string   `json:"workflow_sha"`
	JobWorkflowRef    string   `json:"job_workflow_ref"`
	JobWorkflowSha    string   `json:"job_workflow_sha"`
}

type auditEvent struct {
	Received         time.Time                `json:"received"`
	HTTPStatusCode   int                      `json:"http_status_code"`
	HTTPErrorMessage string                   `json:"http_error_msg"`
	Token            *oidcClaims              `json:"oidc_token_claims"`
	Request          *githubauth.TokenRequest `json:"request"`
	Config           *RepositoryConfig        `json:"repository_config"`
}

// NewRouter creates a new HTTP server implementation that will exchange
// a GitHub OIDC token for a GitHub application token with eleveated privlidges.
func NewRouter(ctx context.Context, githubApp *githubauth.App, configStore ConfigReader, jwtParseOptions []jwt.ParseOption, lumberjackClient *lumberjack.Client) (*TokenMintServer, error) {
	return &TokenMintServer{
		githubApp:        githubApp,
		configStore:      configStore,
		jwtParseOptions:  jwtParseOptions,
		lumberjackClient: lumberjackClient,
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
			logger.ErrorContext(ctx, "error processing request",
				"error", err,
				"code", respCode,
				"body", respMsg)
		}
		auditEvent.HTTPStatusCode = respCode

		// Write the audit information
		if err := s.writeAuditLog(ctx, &auditEvent); err != nil {
			logger.ErrorContext(ctx, "failed to send audit event to lumberjack", "error", err)
			// Fail the request if it could not be audited
			respCode = http.StatusInternalServerError
			respMsg = "failed to persist audit information"
		}

		w.WriteHeader(respCode)
		fmt.Fprint(w, respMsg)
	})
}

// writeAuditLog takes all of the data about the request and its success or failure and
// writes it to cloud logging via Lumberjack.
func (s *TokenMintServer) writeAuditLog(ctx context.Context, auditEvent *auditEvent) error {
	token, err := json.Marshal(auditEvent.Token)
	if err != nil {
		return fmt.Errorf("error marshaling token: %w", err)
	}
	req, err := json.Marshal(auditEvent.Request)
	if err != nil {
		return fmt.Errorf("error marshaling request: %w", err)
	}
	config, err := json.Marshal(auditEvent.Config)
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}

	resourceName := "not specified"
	if auditEvent.Request != nil {
		resourceName = strings.Join(auditEvent.Request.Repositories, ",")
	}
	principal := "unknown"
	if auditEvent.Token != nil {
		principal = auditEvent.Token.WorkflowRef
	}

	logRequest := &api.AuditLogRequest{
		Type: api.AuditLogRequest_ADMIN_ACTIVITY,
		Payload: &audit.AuditLog{
			ServiceName:  "abcxyz.dev/github-token-minter",
			MethodName:   "abcxyz.dev/github-token-minter/HandleTokenRequest",
			ResourceName: resourceName,
			Status: &status.Status{
				Code:    int32(auditEvent.HTTPStatusCode),
				Message: auditEvent.HTTPErrorMessage,
			},
			Request: &structpb.Struct{Fields: map[string]*structpb.Value{
				"token":   structpb.NewStringValue(string(token)),
				"request": structpb.NewStringValue(string(req)),
				"config":  structpb.NewStringValue(string(config)),
			}},
			AuthenticationInfo: &audit.AuthenticationInfo{
				// WorkflowRef: abcxyz/github-token-minter/.github/workflows/integration.yml@refs/pull/8/merge
				PrincipalEmail: principal,
			},
		},
	}

	if err := s.lumberjackClient.Log(ctx, logRequest); err != nil {
		return fmt.Errorf("error writing log with lumberjack: %w", err)
	}
	return nil
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

	var request githubauth.TokenRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64_000))
	if err := dec.Decode(&request); err != nil {
		return http.StatusBadRequest, "error parsing request information - invalid JSON", fmt.Errorf("error parsing request: %w", err)
	}
	auditEvent.Request = &request

	// Parse the token data into a JWT
	parseOpts := append([]jwt.ParseOption{jwt.WithContext(ctx)}, s.jwtParseOptions...)
	oidcToken, err := jwt.Parse([]byte(oidcHeader), parseOpts...)
	if err != nil {
		return http.StatusUnauthorized, fmt.Sprintf("request not authorized: '%s' header is invalid", AuthHeader), fmt.Errorf("failed to validate jwt: %w", err)
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

	// If all repositories are allowed and all were requested,
	// request access token for all allowed repositories for the GitHub app
	if allowRequestAllRepos(perm.Repositories, request.Repositories) {
		allRepoRequest := &githubauth.TokenRequestAllRepos{Permissions: request.Permissions}

		accessToken, err := s.githubApp.AccessTokenAllRepos(ctx, allRepoRequest)
		if err != nil {
			return http.StatusInternalServerError, "error generating GitHub access token", fmt.Errorf("error generating GitHub access token: %w", err)
		}
		return http.StatusOK, accessToken, nil
	}

	// Otherwise, validate that all of the requested repositories are allowed
	// or if all repositories are allowed and specific repositories were requested,
	// request restricted access token
	repos, err := validateRepositories(perm.Repositories, request.Repositories)
	if err != nil {
		return http.StatusForbidden, "one or more of the requested repositories is not authorized", err
	}
	// Replace the requested repository list with actual values
	request.Repositories = repos

	accessToken, err := s.githubApp.AccessToken(ctx, &request)
	if err != nil {
		return http.StatusInternalServerError, "error generating GitHub access token", fmt.Errorf("error generating GitHub access token: %w", err)
	}
	return http.StatusOK, accessToken, nil
}

// allowRequestAllRepos determines if a request is allowed to request
// a token with permissions to all repositories.
func allowRequestAllRepos(allowed, requested []string) bool {
	return len(allowed) == 1 && allowed[0] == "*" &&
		len(requested) == 1 && requested[0] == "*"
}

// validateRepositories checks the set of requested repositories against the allow list
// to verity that it is authorizaed. Response contains the list of allowed repositories
// after wild card match expansion.
func validateRepositories(allowed, requested []string) ([]string, error) {
	// If allow all, return requested
	if len(allowed) == 1 && allowed[0] == "*" {
		return requested, nil
	}

	repositories := []string{}
	// Loop through all of the requested repositories to verifiy that are in the configured
	// allow list
	for _, request := range requested {
		matched := false
		for _, allow := range allowed {
			if matchesAllowed(allow, request) {
				repositories = append(repositories, allow)
				matched = true
			}
		}
		// If there is no match then respond with an error
		if !matched {
			return nil, fmt.Errorf("requested repository %q is not in the allow list", request)
		}
	}
	// Return the set of repositories that are allowed. If no repositories are requested
	// this will result in an empty list which will work for organization level updates
	// such as adding members to teams.
	return repositories, nil
}

func matchesAllowed(allow, request string) bool {
	switch {
	// Matches all repositories in the allow list
	case request == "*":
		return true
	// Prefix matching if given a wildcard e.g. github-*
	case request[len(request)-1] == '*' && strings.HasPrefix(allow, request[:len(request)-1]):
		return true
	// Exact match
	case request == allow:
		return true
	default:
		return false
	}
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
		return "", fmt.Errorf("claim %q not found", claim)
	}
	result, ok := val.(string)
	if required && !ok {
		return "", fmt.Errorf("claim %q not the correct type want=string, got=%T", claim, val)
	}
	return result, nil
}
