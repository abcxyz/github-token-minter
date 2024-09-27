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

	"github.com/abcxyz/pkg/githubauth"
)

const assertionKey string = "assertion"

// GitHubClientProvider is a function that given an org and repo
// will return a properly configured GitHub client object that
// can be used to make API calls to GitHub.
type GitHubClientProvider func(ctx context.Context, org, repo string) (*github.Client, error)

type ConfigEvaluator interface {
	Eval(ctx context.Context, org, repo, scope string, token interface{}) (*Scope, error)
}

type configEvaluator struct {
	loaders []ConfigFileLoader
}

func NewConfigEvaluator(expireAt time.Duration, localConfigDir, repoConfigPath, orgConfigPath, ref string, app *githubauth.App) (*configEvaluator, error) {
	// create an environment to compile any cel expressions
	env, err := cel.NewEnv(cel.Variable(assertionKey, cel.DynType))
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}
	enableCaching := false
	var localLoader, inRepoLoader, orgLoader ConfigFileLoader
	// create and configure all of the file loaders
	if enableCaching {
		localLoader = newCachingConfigLoader(expireAt,
			NewCompilingConfigLoader(env, &localConfigFileLoader{configDir: localConfigDir}))
		inRepoLoader = newCachingConfigLoader(expireAt,
			NewCompilingConfigLoader(env, &ghInRepoConfigFileLoader{
				provider:   makeGitHubClientProvider(app),
				configPath: ".github/minty.yaml",
				ref:        "main",
			}))
		orgLoader = newCachingConfigLoader(expireAt,
			NewCompilingConfigLoader(env, &fixedRepoConfigFileLoader{
				repo: ".google-github",
				loader: &ghInRepoConfigFileLoader{
					provider:   makeGitHubClientProvider(app),
					configPath: "minty.yaml",
					ref:        "main",
				},
			}))
	} else {
		localLoader = NewCompilingConfigLoader(env, &localConfigFileLoader{configDir: localConfigDir})
		inRepoLoader = NewCompilingConfigLoader(env, &ghInRepoConfigFileLoader{
			provider:   makeGitHubClientProvider(app),
			configPath: ".github/minty.yaml",
			ref:        "main",
		})
		orgLoader = NewCompilingConfigLoader(env, &fixedRepoConfigFileLoader{
			repo: ".google-github",
			loader: &ghInRepoConfigFileLoader{
				provider:   makeGitHubClientProvider(app),
				configPath: "minty.yaml",
				ref:        "main",
			},
		})
	}
	return &configEvaluator{
		loaders: []ConfigFileLoader{
			localLoader,
			inRepoLoader,
			orgLoader,
		},
	}, nil
}

func (l *configEvaluator) Eval(ctx context.Context, org, repo, scope string, token interface{}) (*Scope, error) {
	for _, loader := range l.loaders {
		contents, err := loader.Load(ctx, org, repo)
		if err != nil {
			return nil, fmt.Errorf("error reading configuration, child reader threw error: %w", err)
		}
		if contents != nil {
			s, err := contents.Eval(scope, token)
			if err != nil {
				return nil, fmt.Errorf("error evaluating scope: %w", err)
			}
			if s != nil {
				return s, nil
			}
		}
	}
	return nil, fmt.Errorf("error reading configuration, exhausted all possible source locations, failed to locate scope [%s] for repository [%s/%s]", scope, org, repo)
}

func makeGitHubClientProvider(app *githubauth.App) GitHubClientProvider {
	return func(ctx context.Context, org, repo string) (*github.Client, error) {
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
}
