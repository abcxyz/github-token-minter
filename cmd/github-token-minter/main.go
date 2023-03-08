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
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/abcxyz/github-token-minter/pkg/server"
	"github.com/abcxyz/lumberjack/clients/go/pkg/audit"
	"github.com/abcxyz/lumberjack/clients/go/pkg/auditopt"
	"github.com/abcxyz/pkg/cfgloader"
	"github.com/abcxyz/pkg/logging"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// main is the application entry point. It primarily wraps the realMain function with
// a context that properly handles signals from the OS.
func main() {
	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()

	logger := logging.NewFromEnv("")
	ctx = logging.WithLogger(ctx, logger)

	if err := realMain(ctx); err != nil {
		done()
		logger.Fatal(err)
	}
}

// serviceConfig defines the set over environment variables required
// for running this application.
type serviceConfig struct {
	Port           string `env:"PORT,default=8080"`
	AppID          string `env:"GITHUB_APP_ID,required"`
	InstallationID string `env:"GITHUB_INSTALL_ID,required"`
	PrivateKey     string `env:"GITHUB_PRIVATE_KEY,required"`
	JWKSUrl        string `env:"GITHUB_JKWS_URL,default=https://token.actions.githubusercontent.com/.well-known/jwks"`
	// URL used to retrieve access tokens. The pattern must contain a single '%s' which represents where in the url
	// to insert the installation id.
	AccessTokenURLPattern string `env:"GITHUB_ACCESS_TOKEN_URL_PATTERN,default=https://api.github.com/app/installations/%s/access_tokens"`
	ConfigDir             string `env:"CONFIGS_DIR,default=configs"`
	LumberjackConfigFile  string `env:"LUMBERJACK_CONFIG_FILE,default=/etc/lumberjack/config.yaml"`
}

// realMain creates an HTTP server for use with minting GitHub app tokens
// This server supports graceful stopping and cancellation by:
//   - using a cancellable context
//   - listening to incoming requests in a goroutine
func realMain(ctx context.Context) error {
	var cfg serviceConfig
	if err := cfgloader.Load(ctx, &cfg); err != nil {
		return fmt.Errorf("failed to read configuration information: %w", err)
	}
	// Read the private key.
	privateKey, err := readPrivateKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Setup the GitHub App config.
	appConfig := server.GitHubAppConfig{
		AppID:          cfg.AppID,
		InstallationID: cfg.InstallationID,
		PrivateKey:     privateKey,
		AccessTokenURL: cfg.AccessTokenURLPattern,
	}

	// Create an in memory ConfigReader which preloads all of
	// the configuration files into memory.
	store, err := server.NewInMemoryStore(cfg.ConfigDir)
	if err != nil {
		return fmt.Errorf("failed to build configuration cache: %w", err)
	}

	// Setup JWKS verification.
	c := jwk.NewCache(ctx)
	if err := c.Register(cfg.JWKSUrl); err != nil {
		return fmt.Errorf("failed to register JWK url: %w", err)
	}

	// check that cache is correctly set up and certs are available
	if _, err := c.Refresh(ctx, cfg.JWKSUrl); err != nil {
		return fmt.Errorf("failed to retrieve JWK public keys: %w", err)
	}
	jwkKeys := jwk.NewCachedSet(c, cfg.JWKSUrl)

	opts := auditopt.FromConfigFile(ctx, cfg.LumberjackConfigFile)

	// Create the lumberjack client
	lumberjack, err := audit.NewClient(opts)
	if err != nil {
		return fmt.Errorf("failed to create Lumberjack client: %w", err)
	}

	// Create the Router for the token minting server.
	tokenServer, err := server.NewRouter(ctx, appConfig, store, jwkKeys, lumberjack)
	if err != nil {
		return fmt.Errorf("failed to start token mint server: %w", err)
	}

	// Create the server and listen in a goroutine.
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           tokenServer.Routes(),
		ReadHeaderTimeout: 2 * time.Second,
	}
	serverErrCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case serverErrCh <- err:
			default:
			}
		}
	}()

	// Wait for shutdown signal or error from the listener.
	select {
	case err := <-serverErrCh:
		return fmt.Errorf("error from server listener: %w", err)
	case <-ctx.Done():
	}

	// Gracefully shut down the server.
	shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()

	if err := lumberjack.Stop(); err != nil {
		return fmt.Errorf("failed to cleanup lumberjack logging: %w", err)
	}

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}
	return nil
}

// readPrivateKey reads a PEM encouded private key from a string.
func readPrivateKey(privateKeyContent string) (*rsa.PrivateKey, error) {
	parsedKey, _, err := jwk.DecodePEM([]byte(privateKeyContent))
	if err != nil {
		return nil, fmt.Errorf("failed to decode PEM formated key:  %w", err)
	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to convert to *rsa.PrivateKey (got %T)", parsedKey)
	}
	return privateKey, nil
}
