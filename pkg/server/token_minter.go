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
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/github-token-minter/pkg/server/source"
	"github.com/abcxyz/github-token-minter/pkg/version"
	"github.com/abcxyz/pkg/gcputil"
	"github.com/abcxyz/pkg/logging"
)

const (
	AuthHeader  = "X-OIDC-Token"
	JWTCacheKey = "jwt-cache-key"
)

// TokenMinterServer is the implementation of an HTTP server that exchanges
// a GitHub OIDC token for a GitHub application token with eleveated privlidges.
type TokenMinterServer struct {
	sourceSystem source.System
	configStore  config.ConfigEvaluator
	parser       *JWTParser
}

// TokenRequest is a struct that contains the list of repositories and the
// requested permissions / scopes that are requested when generating a new
// installation access token.
type TokenRequest struct {
	OrgName      string            `json:"org_name"`
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
func NewRouter(ctx context.Context, sourceSystem source.System, configStore config.ConfigEvaluator, parser *JWTParser) (*TokenMinterServer, error) {
	return &TokenMinterServer{
		sourceSystem: sourceSystem,
		configStore:  configStore,
		parser:       parser,
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

	var request TokenRequest
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
	claims, apiError := s.parser.ParseAuthToken(ctx, oidcHeader)
	if apiError != nil {
		return apiError
	}

	// Determine the org name to be used for the request
	requestOrgName, apiError := validateOrgName(request.OrgName, claims.ParsedOrgName)
	if apiError != nil {
		return apiError
	}
	request.OrgName = requestOrgName

	// If no repositories are requested, default to the repository from the
	// OIDC token claims. If neither exist then throw an error.
	if len(request.Repositories) == 0 {
		if claims.ParsedRepoName == "" {
			return &apiResponse{
				http.StatusBadRequest,
				"request does not contain required information",
				errors.New(`claim "repository" not found and no "repositories" sent as part of the request`),
			}
		} else {
			request.Repositories = []string{claims.ParsedRepoName}
		}
	}

	logger.InfoContext(ctx, "received token request",
		"claims", claims,
		"request", request,
	)

	repoList, apiErr := buildRepositoryList(ctx, &request, claims, s.configStore)
	if apiErr != nil {
		return apiErr
	}

	// If all repositories are allowed and all were requested,
	// request access token for all allowed repositories
	if isRequestAllRepos(repoList, request.Repositories) {
		logger.InfoContext(ctx, "generating token for all repos",
			"claims", claims,
			"request_repositories", "all",
			"request_permissions", request.Permissions,
		)

		accessToken, err := s.sourceSystem.MintAccessToken(ctx, request.OrgName, claims.ParsedRepoName, nil, request.Permissions)
		if err != nil {
			return &apiResponse{http.StatusInternalServerError, "error generating access token", fmt.Errorf("error generating access token: %w", err)}
		}
		return &apiResponse{http.StatusOK, accessToken, nil}
	}

	// Otherwise, validate that all of the requested repositories are allowed
	// or if all repositories are allowed and specific repositories were requested,
	// request restricted access token
	repos, err := validateRepositories(repoList, request.Repositories)
	if err != nil {
		return &apiResponse{http.StatusForbidden, "one or more of the requested repositories is not authorized", err}
	}
	logger.InfoContext(ctx, "generating token",
		"claims", claims,
		"request_repositories", repos,
		"request_permissions", request.Permissions,
	)

	accessToken, err := s.sourceSystem.MintAccessToken(ctx, requestOrgName, claims.ParsedRepoName, repos, request.Permissions)
	if err != nil {
		return &apiResponse{http.StatusInternalServerError, "error generating access token", fmt.Errorf("error generating access token: %w", err)}
	}
	return &apiResponse{http.StatusOK, accessToken, nil}
}

func validateOrgName(requestOrgName, claimsOrgName string) (string, *apiResponse) {
	orgName := requestOrgName
	// Default the org name to the one parsed from the OIDC token if there is one
	if orgName == "" {
		orgName = claimsOrgName
	}

	// If the request has no org name, and one wasn't found in the OIDC
	// token claims, then throw an error.
	if orgName == "" {
		return "", &apiResponse{
			http.StatusBadRequest,
			fmt.Sprintf("request did not contain an organization name [%s] and one could not be determined from the OIDC token [%s]", requestOrgName, claimsOrgName),
			fmt.Errorf("request did not contain an organization name [%s] and one could not be determined from the OIDC token [%s]", requestOrgName, claimsOrgName),
		}
	}
	return orgName, nil
}

// buildRepositoryList looks for configuration for each of the specified repositories
// in the requested org, finds the matching scope that was requested and then
// verifies that the OIDC claims match the expression attached to the scope.
// This is done against each target repository and any failure to match causes
// the request to fail.
func buildRepositoryList(ctx context.Context, request *TokenRequest, claims *oidcClaims, configStore config.ConfigEvaluator) ([]string, *apiResponse) {
	logger := logging.FromContext(ctx)
	reposSet := make(map[string]string)

	for _, repo := range request.Repositories {
		// Requests for "all repos" can't be handled by an in repo configuration,
		// handle it by forcing the repo name to be the one in the oidc request which
		// will either make it look in that repo OR in the global config file
		if repo == "*" {
			if len(request.Repositories) > 1 {
				// This is a secenario we shouldn't support. Asking for "*" and any other repositories
				// will lead to very strange results.
				return nil, &apiResponse{http.StatusForbidden, "request for '*' also contained request for specific repositories and that is not allowed", errors.New("request for '*' also contained request for specific repositories and that is not allowed")}
			}
			repo = claims.ParsedRepoName
		}
		// Get the repository's configuration data and evaluate the token against the
		// configuration to find a matching scope.
		scope, source, err := configStore.Eval(ctx, request.OrgName, repo, request.Scope, claims.asMap())
		if err != nil {
			return nil, &apiResponse{
				http.StatusInternalServerError,
				fmt.Sprintf("requested scope %q is not found for repository %q/%q", request.Scope, request.OrgName, repo),
				fmt.Errorf("error reading configuration for repository %s/%s from configuration store with config_source %s: %w", request.OrgName, repo, source, err),
			}
		}
		if scope == nil {
			return nil, &apiResponse{http.StatusForbidden, fmt.Sprintf("no permissions available for scope %q in repository %q", request.Scope, claims.Repository), err}
		}

		// If there are no permissions in the request, evaluate what permissions
		// to request based on the scope
		if len(request.Permissions) == 0 {
			// If the scope is defined as "all permissions", then set the value to
			// nil which will request all permissions assigned to the app
			if _, ok := scope.Permissions["*"]; ok {
				request.Permissions = nil
			} else {
				// Otherwise, use the permissions defined in the scope
				request.Permissions = scope.Permissions
			}
		}

		// Validate the permissions that were requested are within what is allowed for the repository
		if err = validatePermissions(scope.Permissions, request.Permissions); err != nil {
			return nil, &apiResponse{http.StatusForbidden, "requested permissions are not authorized for this repository", err}
		}
		logger.InfoContext(ctx, "adding scope to allowed set of repositories",
			"scope", scope,
			"config_source", source,
		)
		for _, s := range scope.Repositories {
			reposSet[s] = s
		}
	}
	tokenRepos := make([]string, 0, len(reposSet))
	for k := range reposSet {
		tokenRepos = append(tokenRepos, k)
	}

	return tokenRepos, nil
}

// isRequestAllRepos determines if a request is allowed to request
// a token with permissions to all repositories.
func isRequestAllRepos(allowed, requested []string) bool {
	return len(requested) == 0 && len(allowed) == 0 || (len(allowed) == 1 && allowed[0] == "*" &&
		len(requested) == 1 && requested[0] == "*")
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
