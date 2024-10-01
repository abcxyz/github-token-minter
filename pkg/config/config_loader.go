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
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/go-github/v64/github"
	"gopkg.in/yaml.v3"

	"github.com/abcxyz/pkg/cache"
)

// ConfigFileLoader represents an object that is capable of
// retrieving a configuration files contents in its raw form.
type ConfigFileLoader interface {
	Load(ctx context.Context, org, repo string) (*Config, error)
}

type cachingConfigFileLoader struct {
	loader ConfigFileLoader
	cache  *cache.Cache[*Config]
}

func newCachingConfigLoader(expireAfter time.Duration, child ConfigFileLoader) ConfigFileLoader {
	return &cachingConfigFileLoader{
		loader: child,
		cache:  cache.New[*Config](expireAfter),
	}
}

type compilingConfigLoader struct {
	loader ConfigFileLoader
	env    *cel.Env
}

func NewCompilingConfigLoader(env *cel.Env, child ConfigFileLoader) ConfigFileLoader {
	return &compilingConfigLoader{
		loader: child,
		env:    env,
	}
}

func (l *compilingConfigLoader) Load(ctx context.Context, org, repo string) (*Config, error) {
	cfg, err := l.loader.Load(ctx, org, repo)
	if err != nil {
		return nil, fmt.Errorf("compiling config loader, sub loader failed to load configuration: %w", err)
	}
	if cfg != nil {
		if err := cfg.compile(l.env); err != nil {
			return nil, fmt.Errorf("failed to compile CEL expressions in config: %w", err)
		}
	}
	return cfg, nil
}

func (l *cachingConfigFileLoader) Load(ctx context.Context, org, repo string) (*Config, error) {
	key := fmt.Sprintf("%s/%s", org, repo)
	// first look for the config object in cache
	cached, exists := l.cache.Lookup(key)
	if exists {
		return cached, nil
	}
	cfg, err := l.loader.Load(ctx, org, repo)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration file for [%s / %s]. Error: %w", org, repo, err)
	}
	l.cache.Set(key, cfg)

	return cfg, nil
}

// localConfigFileLoader is a configFileLoader implementation that
// reads files from the local file system.
type localConfigFileLoader struct {
	configDir string
}

// Load reads the contents of configuration files from the local file system.
func (l *localConfigFileLoader) Load(ctx context.Context, org, repo string) (*Config, error) {
	name := fmt.Sprintf("%s/%s/%s.yaml", l.configDir, org, repo)
	data, err := os.ReadFile(name)
	if err != nil {
		// file not found is not an error
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("error reading content from file: %w", err)
	}
	config, err := Read(data)
	if err != nil {
		return nil, fmt.Errorf("error converting raw config bytes into struct: %w", err)
	}
	return config, nil
}

// ghInRepoConfigFileLoader reads a configuration file from a specific
// path within the requested repository.
type ghInRepoConfigFileLoader struct {
	provider   GitHubClientProvider
	configPath string
	ref        string
}

// Load is a configFileLoader implementation that reads the configuration file
// contents from within a GitHub repository.
func (l *ghInRepoConfigFileLoader) Load(ctx context.Context, org, repo string) (*Config, error) {
	client, err := l.provider(ctx, org, repo)
	if err != nil {
		return nil, fmt.Errorf("error creating GitHub client for %s/%s: %w", org, repo, err)
	}
	fileContents, _, resp, err := client.Repositories.GetContents(ctx, org, repo, l.configPath, &github.RepositoryContentGetOptions{Ref: l.ref})
	if err != nil {
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		} else {
			return nil, fmt.Errorf("error reading configuration file @ %s/%s/%s: %w", org, repo, l.configPath, err)
		}
	}
	if fileContents != nil {
		contents, err := fileContents.GetContent()
		if err != nil {
			return nil, fmt.Errorf("error reading configuration file contents @ %s/%s/%s: %w", org, repo, l.configPath, err)
		}
		config, err := Read([]byte(contents))
		if err != nil {
			return nil, fmt.Errorf("error converting raw config bytes into struct: %w", err)
		}
		return config, nil
	}
	return nil, nil
}

// fixedRepoConfigFileLoader reads the contents of a configuration file from
// a specific repository, not from the target repository. It wraps another
// loader and delegates the retrieval to that implementation after replacing
// the repo parameter.
type fixedRepoConfigFileLoader struct {
	loader ConfigFileLoader
	repo   string
}

// Load is a configFileLoader implementation that retrieves the contents of a
// configuration file from a specific repository in the org, not from the target repository.
func (l *fixedRepoConfigFileLoader) Load(ctx context.Context, org, repo string) (*Config, error) {
	res, err := l.loader.Load(ctx, org, l.repo)
	if err != nil {
		return nil, fmt.Errorf("error reading config file from child loader: %w", err)
	}
	return res, nil
}

func Read(contents []byte) (*Config, error) {
	var config Config
	// default to the latest version of the config format
	if err := yaml.Unmarshal(contents, &config); err != nil {
		// attempt to unmarshal in the old format
		var cv1 v1Document
		if err := yaml.Unmarshal(contents, &cv1); err != nil {
			return nil, fmt.Errorf("error parsing yaml document: %w", err)
		}
		config = NewConfigFromV1(cv1)
	}
	return &config, nil
}
