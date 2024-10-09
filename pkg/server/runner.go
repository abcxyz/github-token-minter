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
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/pkg/githubauth"
	"github.com/abcxyz/pkg/serving"
)

func Run(ctx context.Context, cfg *Config) error {
	// Set the access token url pattern if it is provided.
	var options []githubauth.Option
	if cfg.GitHubAPIBaseURL != "" {
		options = append(options, githubauth.WithBaseURL(cfg.GitHubAPIBaseURL))
	}

	// Setup the GitHub App.
	app, err := githubauth.NewApp(cfg.AppID, cfg.PrivateKey, options...)
	if err != nil {
		return fmt.Errorf("failed to create github app: %w", err)
	}

	cacheSeconds, err := strconv.Atoi(cfg.ConfigCacheSeconds)
	if err != nil {
		return fmt.Errorf("failed to parse config cache seconds as an integer: %w", err)
	}
	if cacheSeconds == 0 {
		// duration must be a positive integer
		cacheSeconds = 1
	}

	store, err := config.NewConfigEvaluator(
		time.Duration(cacheSeconds)*time.Second,
		cfg.ConfigDir,
		cfg.RepoConfigPath,
		cfg.OrgConfigRepo,
		cfg.OrgConfigPath,
		cfg.Ref,
		app,
	)
	if err != nil {
		return fmt.Errorf("failed to create config evaluator: %w", err)
	}

	jwtParseOptions := []jwt.ParseOption{
		jwt.WithAcceptableSkew(5 * time.Second),
	}

	// Create the Router for the token minting server.
	tokenServer, err := NewRouter(ctx, app, store, &JWTParser{ParseOptions: jwtParseOptions, jwkResolver: NewOIDCResolver(ctx)})
	if err != nil {
		return fmt.Errorf("failed to start token mint server: %w", err)
	}

	// Create the server and listen.
	server, err := serving.New(cfg.Port)
	if err != nil {
		return fmt.Errorf("failed to create serving infrastructure: %w", err)
	}
	if err := server.StartHTTPHandler(ctx, tokenServer.Routes(ctx)); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}
	return nil
}
