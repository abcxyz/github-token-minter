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
	"github.com/abcxyz/pkg/logging"
)

const AUTH_HEADER = "X-APIGATEWAY-API-USERINFO"

func HandleTokenRequest(cache config.ConfigCache, w http.ResponseWriter, r *http.Request) {
	logger := logging.FromContext(r.Context())
	_ = logger

	// Retrieve the OIDC token from a header. API Gateway will
	// pass the OIDC token in the X-APIGATEWAY-API-USERINFO header
	oidcToken := r.Header.Get(AUTH_HEADER)
	// Ensure the token is in the header
	if oidcToken == "" {
		w.WriteHeader(403)
		fmt.Fprintf(w, "request not authorized: '%s' header is missing", AUTH_HEADER)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(oidcToken)
	if err != nil {
		w.WriteHeader(403)
		fmt.Fprintf(w, "request not authorized: '%s' header is invalid", AUTH_HEADER)
		return
	}
	var token map[string]string
	err = json.Unmarshal(decoded, &token)
	if err != nil {
		w.WriteHeader(403)
		fmt.Fprintf(w, "request not authorized: '%s' header is invalid", AUTH_HEADER)
		return
	}

	fmt.Fprint(w, "ok.\n") // automatically calls `w.WriteHeader(http.StatusOK)`
}
