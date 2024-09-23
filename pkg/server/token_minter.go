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
	"html"
	"io"
	"net/http"
	"strings"

	"github.com/abcxyz/github-token-minter/pkg/server/config"
	"github.com/abcxyz/github-token-minter/pkg/version"
	"github.com/abcxyz/pkg/gcputil"
	"github.com/abcxyz/pkg/githubauth"
	"github.com/abcxyz/pkg/logging"
)

const (
	AuthHeader  = "X-GitHub-OIDC-Token"
	JWTCacheKey = "github-app-jwt"
)

// TokenMinterServer is the implementation of an HTTP server that exchanges
// a GitHub OIDC token for a GitHub application token with eleveated privlidges.
type TokenMinterServer struct {
	githubApp   *githubauth.App
	configStore config.ConfigEvaluator
	parser      *JWTParser
}

// tokenRequest is a struct that contains the list of repositories and the
// requested permissions / scopes that are requested when generating a new
// installation access token.
type tokenRequest struct {
	Repositories []string          `json:"repositories"`
	Permissions  map[string]string `json:"permissions"`
	Scope        string            `json:"scope"`
}

// apiResponse is a structure that contains a http status code,
// a string response message and any error that might have occurred
// in the processing of a request.
type apiResponse struct {
	Code    int
	Message string
	Error   error
}

// NewRouter creates a new HTTP server implementation that will exchange
// a GitHub OIDC token for a GitHub application token with eleveated privlidges.
func NewRouter(ctx context.Context, githubApp *githubauth.App, configStore config.ConfigEvaluator, parser *JWTParser) (*TokenMinterServer, error) {
	return &TokenMinterServer{
		githubApp:   githubApp,
		configStore: configStore,
		parser:      parser,
	}, nil
}

// handleToken creates a http.HandlerFunc implementation that processes token requests.
func (s *TokenMinterServer) handleToken() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := logging.FromContext(ctx)

		resp := s.processRequest(r)
		if resp.Error != nil {
			logger.ErrorContext(ctx, "error processing request",
				"error", resp.Error,
				"code", resp.Code,
				"body", resp.Message)
		}

		w.WriteHeader(resp.Code)
		fmt.Fprint(w, html.EscapeString(resp.Message))
	})
}

// handleVersion is a simple http.HandlerFunc that responds
// with version information for the server.
func (s *TokenMinterServer) handleVersion() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"version":%q}\n`, version.HumanVersion)
	})
}

// Routes creates a ServeMux of all of the routes that
// this Router supports.
func (s *TokenMinterServer) Routes(ctx context.Context) http.Handler {
	logger := logging.FromContext(ctx)
	projectID := gcputil.ProjectID(ctx)

	middleware := logging.HTTPInterceptor(logger, projectID)

	mux := http.NewServeMux()
	mux.Handle("/token", middleware(s.handleToken()))
	mux.Handle("/version", middleware(s.handleVersion()))
	return mux
}

func (s *TokenMinterServer) processRequest(r *http.Request) *apiResponse {
	ctx := r.Context()
	logger := logging.FromContext(ctx)

	// Retrieve the OIDC token from a header.
	oidcHeader := r.Header.Get(AuthHeader)
	// Ensure the token is in the header
	if oidcHeader == "" {
		return &apiResponse{http.StatusBadRequest, fmt.Sprintf("request not authorized: %q header is missing", AuthHeader), nil}
	}
	// Parse the request information
	defer r.Body.Close()

	var request tokenRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 4_194_304)) // 4 MiB
	if err := dec.Decode(&request); err != nil {
		return &apiResponse{http.StatusBadRequest, "error parsing request information - invalid JSON", fmt.Errorf("error parsing request: %w", err)}
	}

	// In the future we'll reject requests that do not contain a scope but until all
	// v1 config files are updated this is unfeasible. For now just set it to "v1default"
	// and the config evaluator will know what to do with that
	if request.Scope == "" {
		request.Scope = "v1default"
		// return &apiResponse{http.StatusBadRequest, "error parsing request information - missing 'scope' attribute", nil}
	}

	// Parse the auth token into a set of claims
	claims, apiError := s.parser.parseAuthToken(ctx, oidcHeader)
	if apiError != nil {
		return apiError
	}

	// Get the repository's configuration data and evaluate the token against the
	// configuration to find a matching scope.
	scope, err := s.configStore.Eval(ctx, claims.ParsedOrgName, claims.ParsedRepoName, request.Scope, claims.asMap())
	if err != nil {
		return &apiResponse{
			http.StatusInternalServerError,
			fmt.Sprintf("requested scope %q is not found for repository %q", request.Scope, claims.Repository),
			fmt.Errorf("error reading configuration for repository %s from configuration store: %w", claims.Repository, err),
		}
	}
	if scope == nil {
		return &apiResponse{http.StatusForbidden, fmt.Sprintf("no permissions available for scope %q in repository %q", request.Scope, claims.Repository), err}
	}

	// Validate the permissions that were requested are within what is allowed for the repository
	if err = validatePermissions(scope.Permissions, request.Permissions); err != nil {
		return &apiResponse{http.StatusForbidden, "requested permissions are not authorized for this repository", err}
	}

	// Lookup the App installation for the GitHub owner/repo
	installation, err := s.githubApp.InstallationForRepo(ctx, claims.ParsedOrgName, claims.ParsedRepoName)
	if err != nil {
		return &apiResponse{http.StatusInternalServerError, "Failed to find GitHub app installation for repository. Please ensure the app is properly installed.", fmt.Errorf("error retrieving GitHub installation: %w", err)}
	}

	// If all repositories are allowed and all were requested,
	// request access token for all allowed repositories for the GitHub app
	if allowRequestAllRepos(scope.Repositories, request.Repositories) {
		allRepoRequest := &githubauth.TokenRequestAllRepos{Permissions: request.Permissions}

		accessToken, err := installation.AccessTokenAllRepos(ctx, allRepoRequest)
		if err != nil {
			return &apiResponse{http.StatusInternalServerError, "error generating GitHub access token", fmt.Errorf("error generating GitHub access token: %w", err)}
		}
		return &apiResponse{http.StatusOK, accessToken, nil}
	}

	// Otherwise, validate that all of the requested repositories are allowed
	// or if all repositories are allowed and specific repositories were requested,
	// request restricted access token
	repos, err := validateRepositories(scope.Repositories, request.Repositories)
	if err != nil {
		return &apiResponse{http.StatusForbidden, "one or more of the requested repositories is not authorized", err}
	}

	tokenRequest := githubauth.TokenRequest{
		Repositories: repos,
		Permissions:  request.Permissions,
	}
	logger.InfoContext(ctx, "generating token",
		"claims", claims,
		"request", tokenRequest,
		"scope", scope,
	)

	accessToken, err := installation.AccessToken(ctx, &tokenRequest)
	if err != nil {
		return &apiResponse{http.StatusInternalServerError, "error generating GitHub access token", fmt.Errorf("error generating GitHub access token: %w", err)}
	}
	return &apiResponse{http.StatusOK, accessToken, nil}
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
	// Loop through all of the requested repositories to verifiy that they are in the
	// configured allow list
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
