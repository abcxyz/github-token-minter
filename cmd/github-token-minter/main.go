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

// The github-token-minter command is an http server which receives requests
// containing OIDC tokens from GitHub and produces a GitHub application
// level token with elevated privlidges.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/abcxyz/github-token-minter/pkg/server"
	"github.com/abcxyz/github-token-minter/pkg/server/config"
	"github.com/abcxyz/github-token-minter/pkg/version"
	"github.com/abcxyz/pkg/cfgloader"
	"github.com/abcxyz/pkg/githubauth"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/serving"
)

// main is the application entry point. It primarily wraps the realMain function with
// a context that properly handles signals from the OS.
func main() {
	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	logger := logging.NewFromEnv("").
		With("service", version.Name)
	ctx = logging.WithLogger(ctx, logger)

	if err := realMain(ctx); err != nil {
		done()
		logger.ErrorContext(ctx, err.Error())
		os.Exit(1)
	}
}

// serviceConfig defines the set over environment variables required
// for running this application.
type serviceConfig struct {
	Port       string `env:"PORT,default=8080"`
	AppID      string `env:"GITHUB_APP_ID,required"`
	PrivateKey string `env:"GITHUB_PRIVATE_KEY,required"`
	JWKSUrl    string `env:"GITHUB_JKWS_URL,default=https://token.actions.githubusercontent.com/.well-known/jwks"`

	// GitHubAPIBaseURL is the base URL for the GitHub installation. It should
	// include the protocol (https://) and no trailing slashes.
	GitHubAPIBaseURL string `env:"GITHUB_API_BASE_URL"`

	ConfigDir string `env:"CONFIGS_DIR,default=configs"`
	RepoPath  string `env:"REPO_PATH,default=.github/minty.yaml"`
	OrgPath   string `env:"ORG_PATH,default=.google-github/minty.yaml"`
	Ref       string `env:"REF,default=main"`
}

// realMain creates an HTTP server for use with minting GitHub app tokens
// This server supports graceful stopping and cancellation by:
//   - using a cancellable context
//   - listening to incoming requests in a goroutine
func realMain(ctx context.Context) (retErr error) {
	logger := logging.FromContext(ctx)

	logger.InfoContext(ctx, "starting service",
		"version", version.Version,
		"commit", version.Commit)
	defer logger.InfoContext(ctx, "stopping service")

	var cfg serviceConfig
	if err := cfgloader.Load(ctx, &cfg); err != nil {
		return fmt.Errorf("failed to read configuration information: %w", err)
	}

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

	store, err := config.NewConfigEvaluator(1*time.Hour, cfg.ConfigDir, cfg.RepoPath, cfg.OrgPath, cfg.Ref, app)
	if err != nil {
		return fmt.Errorf("failed to create config evaluator: %w", err)
	}

	// Setup JWKS verification.
	jwkCache := jwk.NewCache(ctx)
	if err := jwkCache.Register(cfg.JWKSUrl); err != nil {
		return fmt.Errorf("failed to register jwks endpoint: %w", err)
	}
	jwkCachedSet := jwk.NewCachedSet(jwkCache, cfg.JWKSUrl)
	jwtParseOptions := []jwt.ParseOption{
		jwt.WithKeySet(jwkCachedSet, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithAcceptableSkew(5 * time.Second),
	}

	// Create the Router for the token minting server.
	tokenServer, err := server.NewRouter(ctx, app, store, &server.JWTParser{ParseOptions: jwtParseOptions})
	if err != nil {
		return fmt.Errorf("failed to start token mint server: %w", err)
	}

	// Create the server and listen.
	server, err := serving.New(cfg.Port)
	if err != nil {
		return fmt.Errorf("failed to create serving infrastructure: %w", err)
	}
	return server.StartHTTPHandler(ctx, tokenServer.Routes(ctx))
}
