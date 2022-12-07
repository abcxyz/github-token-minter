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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/abcxyz/minty/pkg/config"
	"github.com/abcxyz/minty/pkg/permissions"
	"github.com/abcxyz/pkg/logging"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const AUTH_HEADER = "X-GitHub-OIDC-Token"

func HandleTokenRequest(appId string, installId string, privateKey *rsa.PrivateKey, cache config.ConfigCache, w http.ResponseWriter, r *http.Request) {
	logger := logging.FromContext(r.Context())

	// Retrieve the OIDC token from a header.
	oidcToken := r.Header.Get(AUTH_HEADER)
	// Ensure the token is in the header
	if oidcToken == "" {
		w.WriteHeader(401)
		fmt.Fprintf(w, "request not authorized: '%s' header is missing", AUTH_HEADER)
		return
	}
	// The token is base64 encoded json, unmarshal it into a simple map
	decoded, err := base64.StdEncoding.DecodeString(oidcToken)
	if err != nil {
		w.WriteHeader(403)
		logger.Errorf("request header is invalid: %w", err)
		fmt.Fprintf(w, "request not authorized: '%s' header is invalid", AUTH_HEADER)
		return
	}
	var tokenMap map[string]interface{}
	err = json.Unmarshal(decoded, &tokenMap)
	if err != nil {
		w.WriteHeader(403)
		logger.Errorf("request header is not valid json '%s': %w", decoded, err)
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
	config, err := cache.ConfigFor(repo)
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
	signedJwt, err := generateGitHubAppJWT(appId, privateKey, tokenMap)
	if err != nil {
		w.WriteHeader(500)
		logger.Errorf("error generating the JWT for GitHub app access: %w", err)
		fmt.Fprintf(w, "error authenticating with GitHub")
	}
	fmt.Printf("JWT: %s\n", string(signedJwt))
	accessToken, err := generateInstallationAccessToken(r.Context(), string(signedJwt), installId, tokenMap, perm)
	if err != nil {
		w.WriteHeader(500)
		logger.Errorf("error generating GitHub access token: %w", err)
		fmt.Fprintf(w, "error generating GitHub access token")
	}
	fmt.Fprint(w, string(accessToken))
}

func generateInstallationAccessToken(ctx context.Context, ghAppJwt string, ghInstallId string, tokenMap map[string]interface{}, perm *config.Config) (string, error) {
	logger := logging.FromContext(ctx)

	requestURL := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", ghInstallId)
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
		return "", fmt.Errorf("error making http request for GitHub installation information %w", err)
	}
	defer res.Body.Close()

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error reading http response for GitHub installation information %w", err)
	}
	if res.StatusCode != 200 {
		logger.Errorf("Failed to retrieve token from GitHub - Status: %s - Body: %s", res.Status, string(b))
		return "", fmt.Errorf("error generating access token")
	}
	return string(b), nil
}

func generateGitHubAppJWT(appId string, privateKey *rsa.PrivateKey, oidcToken map[string]interface{}) ([]byte, error) {
	iat := time.Now()
	exp := iat.Add(time.Minute * time.Duration(10))
	iss := appId

	token, err := jwt.NewBuilder().
		Expiration(exp).
		IssuedAt(iat).
		Issuer(iss).
		Build()
	if err != nil {
		return nil, err
	}

	// @TODO - Remove this
	tokenMap, err := token.AsMap(context.Background())
	fmt.Printf("Token: %v\n", tokenMap)
	if err != nil {
		return nil, err
	}

	return jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
}
