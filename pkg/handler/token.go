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

const AUTH_HEADER = "X-APIGATEWAY-API-USERINFO"

func HandleTokenRequest(appId string, privateKey *rsa.PrivateKey, cache config.ConfigCache, w http.ResponseWriter, r *http.Request) {
	logger := logging.FromContext(r.Context())

	// Retrieve the OIDC token from a header. API Gateway will
	// pass the OIDC token in the X-APIGATEWAY-API-USERINFO header
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
	_ = perm

	// Create a JWT for reading instance information from GitHub
	signedJwt, err := generateGitHubAppJWT(appId, privateKey, tokenMap)
	if err != nil {
		w.WriteHeader(500)
		logger.Errorf("error generating the JWT for GitHub app access: %w", err)
		fmt.Fprintf(w, "error authenticating with GitHub")
	}
	fmt.Printf("JWT: %s\n", string(signedJwt))
	getGitHubInstallationId(string(signedJwt), tokenMap)

	fmt.Fprint(w, "ok.\n") // automatically calls `w.WriteHeader(http.StatusOK)`
}

func getGitHubInstallationId(ghAppJwt string, oidcToken map[string]interface{}) (string, error) {
	// curl -i -X GET \ -H "Authorization: Bearer YOUR_JWT" -H "Accept: application/vnd.github+json" https://api.github.com/app/installations
	requestURL := "https://api.github.com/app/installations"
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating http request for GitHub installation information %w", err)
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

	fmt.Printf("Token Response Status: %s\n", res.Status)
	fmt.Println(string(b))

	return "", nil
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

	tokenMap, err := token.AsMap(context.Background())

	fmt.Printf("Token: %v\n", tokenMap)
	if err != nil {
		return nil, err
	}
	return jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
}
