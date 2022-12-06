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
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abcxyz/pkg/logging"
	"go.uber.org/zap"

	"github.com/abcxyz/minty/pkg/config"
	"github.com/abcxyz/minty/pkg/handler"
)

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

type server struct {
	cache      config.ConfigCache
	privateKey *rsa.PrivateKey
	appId      string
	installId  string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	handler.HandleTokenRequest(s.appId, s.installId, s.privateKey, s.cache, w, r)
}

// realMain creates an HTTP server for use with minting GitHub app tokens
// This server supports graceful stopping and cancellation by:
//   - using a cancellable context
//   - listening to incoming requests in a goroutine
func realMain(ctx context.Context) error {
	logger := logging.FromContext(ctx)
	// Secretes injected from Secret Manager as environment variables
	ghAppId := os.Getenv("GITHUB_APP_ID")
	if ghAppId == "" {
		return fmt.Errorf("invalid configuration, missing environment variable 'GITHUB_APP_ID'")
	}
	ghInstallId := os.Getenv("GITHUB_INSTALL_ID")
	if ghAppId == "" {
		return fmt.Errorf("invalid configuration, missing environment variable 'GITHUB_INSTALL_ID'")
	}
	ghPrivateKey := os.Getenv("GITHUB_PRIVATE_KEY")
	if ghPrivateKey == "" {
		return fmt.Errorf("invalid configuration, missing environment variable 'GITHUB_PRIVATE_KEY'")
	}
	privateKey, err := readPrivateKey(ghPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	// Build the configuration cache
	configDir := os.Getenv("CONFIGS_DIR")
	if configDir == "" {
		configDir = "configs"
		logger.Debug("defaulting to configuration sourced from ", zap.String("configDir", configDir))
	}
	cache, err := config.NewMemoryConfigCache(configDir)
	if err != nil {
		return fmt.Errorf("failed to build configuration cache: %w", err)
	}
	_ = cache

	mux := http.NewServeMux()
	mux.HandleFunc("/version", handler.HandleVersionRequest)
	mux.Handle("/token", &server{cache: cache, appId: ghAppId, installId: ghInstallId, privateKey: privateKey})

	// Determine port for HTTP service.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		logger.Debug("defaulting to port ", zap.String("port", port))
	}

	// Create the server and listen in a goroutine.
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
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
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}
	return nil
}

func readPrivateKey(privateKeyContent string) (*rsa.PrivateKey, error) {
	privPem, _ := pem.Decode([]byte(privateKeyContent))
	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("error RSA private key is of the wrong type: '%s'", privPem.Type)
	}

	privPemBytes := privPem.Bytes
	var parsedKey interface{}
	// Try a PKCS1 Private Key first
	parsedKey, err := x509.ParsePKCS1PrivateKey(privPemBytes)
	if err != nil {
		// If that fails try a PKCS 8 Private Key
		parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse RSA private key: %w", err)
		}

	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Unable to parse RSA private key: %w", err)
	}
	return privateKey, nil
}
