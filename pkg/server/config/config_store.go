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

package config

import (
	"context"
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/go-github/v64/github"
	"gopkg.in/yaml.v3"

	"github.com/abcxyz/pkg/cache"
	"github.com/abcxyz/pkg/githubauth"
)

const assertionKey string = "assertion"

// GitHubClientProvider is a function that given an org and repo
// will return a properly configured GitHub client object that
// can be used to make API calls to GitHub.
type GitHubClientProvider func(ctx context.Context, org, repo string) (*github.Client, error)

// ConfigStore is a container for Config data that can
// be loaded from various sources. The Config file contents
// are retrieved, parsed and then cached before being returned.
// Config objects expire after the specified amount of time and
// are re-retrieved.
type ConfigStore struct {
	loader configFileLoader
	cache  *cache.Cache[*Config]
}

// NewConfigStore creates a ConfigStore object with the specfied cache
// expiration time, local configuration directory and a GitHub App for
// authenticating GitHub requests.
func NewConfigStore(expireAfter time.Duration, localConfigDir string, app *githubauth.App) *ConfigStore {
	// create and configure all of the file loaders
	localLoader := localConfigFileLoader{configDir: localConfigDir}
	inRepoLoader := ghInRepoConfigFileLoader{
		provider: func(ctx context.Context, org, repo string) (*github.Client, error) {
			return makeGitHubClient(ctx, app, org, repo)
		},
		configPath: ".github/minty.yaml",
		ref:        "main",
	}
	orgLoader := fixedRepoConfigFileLoader{
		repo: ".google-github",
		loader: &ghInRepoConfigFileLoader{
			provider: func(ctx context.Context, org, repo string) (*github.Client, error) {
				return makeGitHubClient(ctx, app, org, repo)
			},
			configPath: "minty.yaml",
			ref:        "main",
		},
	}

	// build the ConfigStore object and setup the cache
	store := &ConfigStore{
		loader: &orderedConfigFileLoader{
			loaders: []configFileLoader{
				&localLoader,
				&inRepoLoader,
				&orgLoader,
			},
		},
		cache: cache.New[*Config](expireAfter),
	}
	return store
}

// Get retrieves a Config object for the org_name / repo_name combination.
func (s *ConfigStore) Read(ctx context.Context, org, repo string) (*Config, error) {
	key := fmt.Sprintf("%s/%s", org, repo)
	// first look for the config object in cache
	cached, exists := s.cache.Lookup(key)
	if exists {
		return cached, nil
	}

	// load the configuration file and then parse its content into a Config object
	contents, err := s.loader.load(ctx, org, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration file for [%s / %s]. Error: %w", org, repo, err)
	}
	// read the contents into a struct
	cfg, err := read(contents)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file contents for [%s / %s]. Error: %w", org, repo, err)
	}
	// compile any cel expressions
	env, err := cel.NewEnv(cel.Variable(assertionKey, cel.DynType))
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}
	if err := cfg.compile(env); err != nil {
		return nil, fmt.Errorf("failed to compile CEL expressions in config: %w", err)
	}
	// Add the config to the cache
	s.cache.Set(key, cfg)

	return cfg, nil
}

func read(contents []byte) (*Config, error) {
	var config Config
	// default to the latest version, if its not set in the document we assume it is the latest
	config.Version = latestConfigVersion
	if err := yaml.Unmarshal(contents, &config); err != nil {
		return nil, fmt.Errorf("error parsing yaml document: %w", err)
	}
	if config.Version != latestConfigVersion {
		return nil, fmt.Errorf("unsupported configuration document version [%s]", config.Version)
	}
	return &config, nil
}

func makeGitHubClient(ctx context.Context, app *githubauth.App, org, repo string) (*github.Client, error) {
	installation, err := app.InstallationForRepo(ctx, org, repo)
	if err != nil {
		return nil, fmt.Errorf("error getting installation for [%s/%s]: %w", org, repo, err)
	}
	token, err := installation.AccessToken(ctx, &githubauth.TokenRequest{
		Repositories: []string{
			repo,
		},
		Permissions: map[string]string{
			"contents": "read",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error getting access token for [%s/%s]: %w", org, repo, err)
	}
	client := github.NewClient(nil).WithAuthToken(token)
	return client, nil
}
