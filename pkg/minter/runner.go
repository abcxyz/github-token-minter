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

// The minter package contains a CLI command that can be used to call the minty
// server to mint a new token.
package minter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/github-token-minter/pkg/server"
	"github.com/abcxyz/pkg/logging"
)

// Run is the main entry point for the minter command.
// It verifies that the passed in token is valid and then
// sends a request to the Minty server to exchange the token.
func Run(ctx context.Context, cfg *Config) error {
	logger := logging.FromContext(ctx)
	httpClient := &http.Client{Timeout: 10 * time.Second}

	jwtParseOptions := []jwt.ParseOption{
		jwt.WithAcceptableSkew(5 * time.Second),
	}
	issuerAllowList := []string{config.GitHubIssuer, config.GoogleIssuer}

	jwkResolver := server.NewOIDCResolver(ctx, issuerAllowList, 4*time.Hour)
	jwtParser := server.JWTParser{ParseOptions: jwtParseOptions, JWKResolver: jwkResolver}

	// Validate that the token is usable before sending it to minty
	claims, apiError := jwtParser.ParseAuthToken(ctx, cfg.Token)
	if apiError != nil {
		return apiError.Internal
	}

	var request server.TokenRequest
	dec := json.NewDecoder(strings.NewReader(cfg.Request))
	if err := dec.Decode(&request); err != nil {
		return fmt.Errorf("error parsing request: %w", err)
	}

	logger.InfoContext(ctx, "received token request",
		"claims", claims,
		"request", cfg.Request,
	)

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("error marshalling request data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/token", cfg.MintyURL), bytes.NewReader(requestJSON))
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.Token))
	req.Header.Set("X-OIDC-Token", cfg.Token)

	res, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make http request: %w", err)
	}
	defer res.Body.Close()

	b, err := io.ReadAll(io.LimitReader(res.Body, 4_194_304)) // 4 MiB
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if got, want := res.StatusCode, http.StatusOK; got != want {
		return fmt.Errorf("invalid http response status (expected %d to be %d): %s", got, want, string(b))
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return fmt.Errorf("failed to parse response as json: %w: %s", err, string(b))
	}

	logger.InfoContext(ctx, resp.Token)

	return nil
}
