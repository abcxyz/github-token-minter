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
	"crypto"
	"fmt"
	"regexp"
	"strconv"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/sethvargo/go-gcpkms/pkg/gcpkms"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/github-token-minter/pkg/server/source"
	"github.com/abcxyz/pkg/githubauth"
	"github.com/abcxyz/pkg/serving"
)

const (
	KeyTypePrivateKey = "private_key"
	KeyTypeKMSID      = "kms_id"
)

func Run(ctx context.Context, cfg *Config) error {
	appConfigs, err := createAppConfigs(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to generate app configs: %w", err)
	}

	sourceSystem, err := source.NewGitHubSourceSystem(ctx, appConfigs, cfg.SourceSystemAPIBaseURL)
	if err != nil {
		return fmt.Errorf("failed to initialize source system: %w", err)
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
		sourceSystem,
	)
	if err != nil {
		return fmt.Errorf("failed to create config evaluator: %w", err)
	}

	jwtParseOptions := []jwt.ParseOption{
		jwt.WithAcceptableSkew(5 * time.Second),
	}

	jwkResolver := NewOIDCResolver(ctx, cfg.IssuerAllowlist, cfg.JWKSCacheDuration)

	// Create the Router for the token minting server.
	tokenServer, err := NewRouter(ctx, sourceSystem, store, &JWTParser{ParseOptions: jwtParseOptions, JWKResolver: jwkResolver})
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

func createAppConfigs(ctx context.Context, cfg *Config) ([]*source.GitHubAppConfig, error) {
	appConfigs := make([]*source.GitHubAppConfig, 0, len(cfg.SourceSystemAuth))

	re, err := regexp.Compile(SourceSystemAuthConfigRegex)
	if err != nil {
		return nil, fmt.Errorf("failed to compile source system regular expression: %w", err)
	}

	for _, auth := range cfg.SourceSystemAuth {
		matches := re.FindAllStringSubmatch(auth, -1)
		if len(matches) != 1 {
			return nil, fmt.Errorf("invalid source system authentication uri: %s - multiple matches for individual system", auth)
		}
		// 0 = full string, 1 = app id, 2 = key type, 3 = key contents
		if len(matches[0]) != 4 {
			return nil, fmt.Errorf("incorrect source system authentication uri: %s - should match expression %s", auth, SourceSystemAuthConfigRegex)
		}
		uri := matches[0]

		appID := uri[1]
		keyType := uri[2]
		keyMaterial := uri[3]

		var signer crypto.Signer
		switch keyType {
		case KeyTypePrivateKey:
			signer, err = githubauth.NewPrivateKeySigner(keyMaterial)
			if err != nil {
				return nil, fmt.Errorf("failed to create private key signer: %w", err)
			}
		case KeyTypeKMSID:
			signer, err = newKMSSigner(ctx, keyMaterial)
			if err != nil {
				return nil, fmt.Errorf("failed to create kms signer: %w", err)
			}
		default:
			return nil, fmt.Errorf("invalid key type: %s", keyType)
		}

		appConfigs = append(appConfigs, &source.GitHubAppConfig{
			AppID:  appID,
			Signer: signer,
		})
	}
	return appConfigs, nil
}

func newKMSSigner(ctx context.Context, keyID string) (crypto.Signer, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup kms client: %w", err)
	}
	signer, err := gcpkms.NewSigner(ctx, client, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms signer: %w", err)
	}
	return signer, nil
}
