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

	"github.com/abcxyz/github-token-minter/pkg/server/source"
)

const (
	AssertionKey string = "assertion"
	IssuersKey   string = "issuers"
)

// GitHubClientProvider is a function that given an org and repo
// will return a properly configured GitHub client object that
// can be used to make API calls to GitHub.
type GitHubClientProvider func(ctx context.Context, org, repo string) (*github.Client, error)

type ConfigEvaluator interface {
	// Eval looks for a configuration for the combination of org and repo that contains
	// the requested scope. If a match is made the scope is returned. This function also
	// returns a string that represents the path to where the scope came from or the file that
	// was being evaluated when an error occurred. This could be a local file path or a remote
	// system such as GitHub.
	Eval(ctx context.Context, org, repo, scope string, token interface{}) (*Scope, string, error)
}

type configEvaluator struct {
	loaders []ConfigFileLoader
}

func NewConfigEvaluator(expireAt time.Duration, localConfigDir, repoConfigPath, orgConfigRepo, orgConfigPath, ref string, sourceSystem source.System) (*configEvaluator, error) {
	// create an environment to compile any cel expressions
	env, err := cel.NewEnv(
		cel.Variable(AssertionKey, cel.DynType),
		cel.Variable(IssuersKey, cel.DynType),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}
	// create and configure all of the file loaders
	localLoader := newCachingConfigLoader(expireAt,
		NewCompilingConfigLoader(env, &localConfigFileLoader{configDir: localConfigDir}))
	inRepoLoader := newCachingConfigLoader(expireAt,
		NewCompilingConfigLoader(env, &inRepoConfigFileLoader{
			sourceSystem: sourceSystem,
			configPath:   repoConfigPath,
			ref:          ref,
		}))
	orgLoader := newCachingConfigLoader(expireAt,
		NewCompilingConfigLoader(env, &fixedRepoConfigFileLoader{
			repo: orgConfigRepo,
			loader: &inRepoConfigFileLoader{
				sourceSystem: sourceSystem,
				configPath:   orgConfigPath,
				ref:          ref,
			},
		}))
	return &configEvaluator{
		loaders: []ConfigFileLoader{
			localLoader,
			inRepoLoader,
			orgLoader,
		},
	}, nil
}

func (l *configEvaluator) Eval(ctx context.Context, org, repo, scope string, token interface{}) (*Scope, string, error) {
	for _, loader := range l.loaders {
		source := loader.Source(org, repo)
		contents, err := loader.Load(ctx, org, repo)
		if err != nil {
			return nil, source, fmt.Errorf("error reading configuration, child reader threw error: %w", err)
		}
		if contents != nil {
			s, err := contents.Eval(scope, token)
			if err != nil {
				return nil, source, fmt.Errorf("error evaluating scope: %w", err)
			}
			if s != nil {
				return s, source, nil
			}
		}
	}
	return nil, fmt.Sprintf("%s/%s", org, repo), fmt.Errorf("error reading configuration, exhausted all possible source locations, failed to locate scope [%s] for repository [%s/%s]", scope, org, repo)
}
