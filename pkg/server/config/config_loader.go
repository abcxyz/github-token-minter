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
	"os"

	"github.com/google/go-github/v64/github"
)

// configFileLoader represents an object that is capable of
// retrieving a configuration files contents in its raw form.
type configFileLoader interface {
	load(ctx context.Context, org, repo string) ([]byte, error)
}

// orderedConfigFileLoader is a configFileLoader implementation
// that delegates to its children in a specific order.
type orderedConfigFileLoader struct {
	loaders []configFileLoader
}

// load on orderedConfigFileLoader is a configFileLoader implementation
// that uses a series of child loaders in a specific order
// and returns the first result that is found.
func (l *orderedConfigFileLoader) load(ctx context.Context, org, repo string) ([]byte, error) {
	for _, loader := range l.loaders {
		contents, err := loader.load(ctx, org, repo)
		if err != nil {
			return nil, fmt.Errorf("error reading configuration, child reader threw error: %w", err)
		}
		if contents != nil {
			return contents, nil
		}
	}
	return nil, fmt.Errorf("error reading configuration, exhausted all possible source locations")
}

// localConfigFileLoader is a configFileLoader implementation that
// reads files from the local file system.
type localConfigFileLoader struct {
	configDir string
}

// load reads the contents of configuration files from the local file system.
func (l *localConfigFileLoader) load(ctx context.Context, org, repo string) ([]byte, error) {
	name := fmt.Sprintf("%s/%s/%s.yaml", l.configDir, org, repo)
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("error reading content from file: %w", err)
	}
	return data, nil
}

// ghInRepoConfigFileLoader reads a configuration file from a specific
// path within the requested repository.
type ghInRepoConfigFileLoader struct {
	provider   GitHubClientProvider
	configPath string
	ref        string
}

// load is a configFileLoader implementation that reads the configuration file
// contents from within a GitHub repository.
func (l *ghInRepoConfigFileLoader) load(ctx context.Context, org, repo string) ([]byte, error) {
	client, err := l.provider(ctx, org, repo)
	if err != nil {
		return nil, fmt.Errorf("error creating GitHub client for %s/%s: %w", org, repo, err)
	}
	fileContents, _, _, err := client.Repositories.GetContents(ctx, org, repo, l.configPath, &github.RepositoryContentGetOptions{Ref: l.ref})
	if err != nil {
		return nil, fmt.Errorf("error reading configuration file @ %s/%s/%s: %w", org, repo, l.configPath, err)
	}
	if fileContents != nil {
		contents, err := fileContents.GetContent()
		if err != nil {
			return nil, fmt.Errorf("error reading configuration file contents @ %s/%s/%s: %w", org, repo, l.configPath, err)
		}
		return []byte(contents), nil
	}
	return nil, nil
}

// fixedRepoConfigFileLoader reads the contents of a configuration file from
// a specific repository, not from the target repository. It wraps another
// loader and delegates the retrieval to that implementation after replacing
// the repo parameter.
type fixedRepoConfigFileLoader struct {
	loader configFileLoader
	repo   string
}

// load is a configFileLoader implementation that retrieves the contents of a
// configuration file from a specific repository in the org, not from the target repository.
func (l *fixedRepoConfigFileLoader) load(ctx context.Context, org, repo string) ([]byte, error) {
	res, err := l.loader.load(ctx, org, l.repo)
	if err != nil {
		return nil, fmt.Errorf("error reading config file from child loader: %w", err)
	}
	return res, nil
}
