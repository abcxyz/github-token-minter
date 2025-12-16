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
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/abcxyz/github-token-minter/pkg/config"
)

// JWTParser is an object that is responsible for parsing
// a JWT auth token into a set of OIDC claims.
type JWTParser struct {
	ParseOptions []jwt.ParseOption
	JWKResolver  JWKResolver
}

// oidcClaims is an object that contains all of the expected
// claims presented by an auth token. Additional values are
// added to the struct to pre-process some of the claims into
// more usable forms such and org and repo names in the
// correct format.
type oidcClaims struct {
	Audience []string `json:"aud"`
	Subject  string   `json:"sub"`
	Issuer   string   `json:"iss"`

	// GitHub claims
	Ref               string `json:"ref"`
	RefType           string `json:"ref_type"`
	Sha               string `json:"sha"`
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	RunID             string `json:"run_id"`
	RunNumber         string `json:"run_number"`
	Actor             string `json:"actor"`
	ActorID           string `json:"actor_id"`
	EventName         string `json:"event_name"`
	Workflow          string `json:"workflow"`
	WorkflowRef       string `json:"workflow_ref"`
	WorkflowSha       string `json:"workflow_sha"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
	JobWorkflowSha    string `json:"job_workflow_sha"`
	ParsedOrgName     string `json:"parsed_org_name"`
	ParsedRepoName    string `json:"parsed_repo_name"`
	EnterpriseName    string `json:"enterprise"`
	EnterpriseID      string `json:"enterprise_id"`

	// Google claims
	Email string `json:"email"`
}

// asMap converts the struct into a map of strings which
// can be used for CEL evaluation.
func (c *oidcClaims) asMap() map[string]interface{} {
	return map[string]interface{}{
		"aud":                 c.Audience,
		"sub":                 c.Subject,
		"iss":                 c.Issuer,
		"ref":                 c.Ref,
		"ref_type":            c.RefType,
		"sha":                 c.Sha,
		"repository":          c.Repository,
		"repository_id":       c.RepositoryID,
		"repository_owner":    c.RepositoryOwner,
		"repository_owner_id": c.RepositoryOwnerID,
		"run_id":              c.RunID,
		"run_number":          c.RunNumber,
		"actor":               c.Actor,
		"actor_id":            c.ActorID,
		"event_name":          c.EventName,
		"workflow":            c.Workflow,
		"workflow_ref":        c.WorkflowRef,
		"workflow_sha":        c.WorkflowSha,
		"job_workflow_ref":    c.JobWorkflowRef,
		"job_workflow_sha":    c.JobWorkflowSha,
		"parsed_org_name":     c.ParsedOrgName,
		"parsed_repo_name":    c.ParsedRepoName,
		"email":               c.Email,
		"enterprise":          c.EnterpriseName,
		"enterprise_id":       c.EnterpriseID,
	}
}

// ParseAuthToken converts a JWT token into a collection of OIDC claims.
func (p *JWTParser) ParseAuthToken(ctx context.Context, oidcHeader string) (*oidcClaims, *apiResponse) {
	keySet, err := p.JWKResolver.ResolveKeySet(ctx, oidcHeader)
	if err != nil {
		return nil, &apiResponse{
			Code:     http.StatusUnauthorized,
			ErrCode:  ErrCodeUnauthorized,
			Message:  "request not authorized: could not resolve JWK keys",
			Internal: fmt.Errorf("failed to validate jwt: %w", err),
		}
	}
	// Parse the token data into a JWT
	parseOpts := append([]jwt.ParseOption{jwt.WithContext(ctx), jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true))}, p.ParseOptions...)
	oidcToken, err := jwt.Parse([]byte(oidcHeader), parseOpts...)
	if err != nil {
		return nil, &apiResponse{
			Code:     http.StatusUnauthorized,
			ErrCode:  ErrCodeUnauthorized,
			Message:  fmt.Sprintf("request not authorized: %q header is invalid", AuthHeader),
			Internal: fmt.Errorf("failed to validate jwt: %w", err),
		}
	}

	claims, err := parsePrivateClaims(oidcToken)
	if err != nil {
		return nil, &apiResponse{
			Code:     http.StatusBadRequest,
			ErrCode:  ErrCodeInvalidRequest,
			Message:  fmt.Sprintf("request does not contain required information: %v", err),
			Internal: err,
		}
	}
	return claims, nil
}

// parsePrivateClaims extracts the private claims from the OIDC token into an internal
// representation and validates that all required claims are present.
func parsePrivateClaims(oidcToken jwt.Token) (*oidcClaims, error) {
	var claims oidcClaims

	claims.Audience = oidcToken.Audience()
	claims.Subject = oidcToken.Subject()
	claims.Issuer = oidcToken.Issuer()

	r, err := extractRepository(oidcToken)
	if err != nil {
		return nil, err
	}
	claims.Repository = r

	claims.Ref = optionalClaim[string](oidcToken, "ref")
	claims.RefType = optionalClaim[string](oidcToken, "ref_type")
	claims.Sha = optionalClaim[string](oidcToken, "sha")
	claims.RepositoryID = optionalClaim[string](oidcToken, "repository_id")
	claims.RepositoryOwner = optionalClaim[string](oidcToken, "repository_owner")
	claims.RepositoryOwnerID = optionalClaim[string](oidcToken, "repository_owner_id")
	claims.RunID = optionalClaim[string](oidcToken, "run_id")
	claims.RunNumber = optionalClaim[string](oidcToken, "run_number")
	claims.Actor = optionalClaim[string](oidcToken, "actor")
	claims.ActorID = optionalClaim[string](oidcToken, "actor_id")
	claims.EventName = optionalClaim[string](oidcToken, "event_name")
	claims.Workflow = optionalClaim[string](oidcToken, "workflow")
	claims.WorkflowRef = optionalClaim[string](oidcToken, "workflow_ref")
	claims.WorkflowSha = optionalClaim[string](oidcToken, "workflow_sha")
	claims.JobWorkflowRef = optionalClaim[string](oidcToken, "job_workflow_ref")
	claims.JobWorkflowSha = optionalClaim[string](oidcToken, "job_workflow_sha")
	claims.EnterpriseName = optionalClaim[string](oidcToken, "enterprise")
	claims.EnterpriseID = optionalClaim[string](oidcToken, "enterprise_id")

	emailVerified := optionalClaim[bool](oidcToken, "email_verified")
	if emailVerified {
		claims.Email = optionalClaim[string](oidcToken, "email")
	}

	// The repository claim from GitHub is of the form <org_name>/<repo_name>.
	// Use this string split instead of attempting to use this and the repository_owner claim since
	// the repository_owner claim is optional.
	// For GCP SA claims, this will be "". We will require that those be set on the request
	// itself for SA access.

	repoParts := strings.Split(claims.Repository, "/")
	if len(repoParts) != 2 && claims.Issuer == config.GitHubIssuer {
		return nil, fmt.Errorf("'repository' claim formatted incorrectly, requires <org_name>/<repo_name> format - received [%s]", claims.Repository)
	}

	if len(repoParts) == 2 {
		claims.ParsedOrgName = repoParts[0]
		claims.ParsedRepoName = repoParts[1]
	}

	return &claims, nil
}

func extractRepository(oidcToken jwt.Token) (string, error) {
	// GoogleIssuer does not have a repository claim
	// All other token issuers as of this time will have the repository claim.
	if oidcToken.Issuer() != config.GoogleIssuer {
		return requiredClaim[string](oidcToken, "repository")
	}
	return "", nil
}

func requiredClaim[T any](oidcToken jwt.Token, claim string) (T, error) {
	return tokenClaim[T](oidcToken, claim, true)
}

func optionalClaim[T any](oidcToken jwt.Token, claim string) T {
	// Intentionally dropping the error here since the existence of the claim does not matter
	result, _ := tokenClaim[T](oidcToken, claim, false)
	return result
}

func tokenClaim[T any](oidcToken jwt.Token, claim string, required bool) (T, error) {
	val, ok := oidcToken.Get(claim)
	var zero T
	if required && !ok {
		return zero, fmt.Errorf("claim %q not found", claim)
	}
	result, ok := val.(T)
	if required && !ok {
		return zero, fmt.Errorf("claim %q not the correct type want=string, got=%T", claim, val)
	}
	return result, nil
}
