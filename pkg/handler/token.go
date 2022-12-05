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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/abcxyz/minty/pkg/config"
	"github.com/abcxyz/minty/pkg/permissions"
	"github.com/abcxyz/pkg/logging"
)

const AUTH_HEADER = "X-APIGATEWAY-API-USERINFO"

func HandleTokenRequest(cache config.ConfigCache, w http.ResponseWriter, r *http.Request) {
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
	decoded, err := base64.StdEncoding.DecodeString(oidcToken)
	if err != nil {
		w.WriteHeader(403)
		fmt.Fprintf(w, "request not authorized: '%s' header is invalid", AUTH_HEADER)
		return
	}
	var tokenMap map[string]string
	err = json.Unmarshal(decoded, &tokenMap)
	if err != nil {
		w.WriteHeader(403)
		fmt.Fprintf(w, "request not authorized: '%s' header is invalid", AUTH_HEADER)
		return
	}
	repo, ok := tokenMap["repository"]
	if !ok {
		w.WriteHeader(500)
		fmt.Fprintf(w, "request does not contain repository information")
		return
	}
	config, err := cache.ConfigFor(repo)
	if err != nil {
		w.WriteHeader(500)
		logger.Errorf("error reading configuration for repository %s from cache: %w", repo, err)
		fmt.Fprintf(w, "requested repository is not properly configured '%s'", repo)
		return
	}

	perm, err := permissions.GetPermissionsForToken(config, tokenMap)
	if err != nil {
		w.WriteHeader(403)
		logger.Errorf("error evaluating permissions: %w", err)
		fmt.Fprintf(w, "no permissions available")
		return
	}
	_ = perm

	fmt.Fprint(w, "ok.\n") // automatically calls `w.WriteHeader(http.StatusOK)`
}
