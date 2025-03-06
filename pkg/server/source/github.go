// Copyright 2025 The Authors (see AUTHORS file)
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

package source

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-github/v64/github"

	"github.com/abcxyz/pkg/githubauth"
)

type GitHubAppConfig struct {
	AppID  string
	Signer crypto.Signer
}

type gitHubSourceSystem struct {
	apps    []*githubauth.App
	baseURL string
}

func NewGitHubSourceSystem(ctx context.Context, configs []*GitHubAppConfig, systemURL string) (System, error) {
	// Set the access token url pattern if it is provided.
	var options []githubauth.Option
	if systemURL != "" {
		options = append(options, githubauth.WithBaseURL(systemURL))
	}
	apps := make([]*githubauth.App, len(configs))
	for ix, cfg := range configs {
		var err error
		// Setup the GitHub App.
		app, err := githubauth.NewApp(cfg.AppID, cfg.Signer, options...)
		if err != nil {
			return nil, fmt.Errorf("failed to create github app: %w", err)
		}
		apps[ix] = app
	}
	return &gitHubSourceSystem{apps, systemURL}, nil
}

// MintAccessToken implements SourceSystem.
func (g *gitHubSourceSystem) MintAccessToken(ctx context.Context, org, repo string, repositories []string, permissions map[string]string) (string, error) {
	var errs []error
	var installation *githubauth.AppInstallation
	var err error
	for _, app := range g.apps {
		installation, err = app.InstallationForRepo(ctx, org, repo)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) != 0 {
		return "", fmt.Errorf("errors retrieving GitHub installation: %w", errors.Join(errs...))
	}
	if repositories == nil {
		allRepoRequest := &githubauth.TokenRequestAllRepos{Permissions: permissions}

		accessToken, err := installation.AccessTokenAllRepos(ctx, allRepoRequest)
		if err != nil {
			return "", fmt.Errorf("error generating GitHub access token: %w", err)
		}
		return accessToken, nil
	}
	tokenRequest := githubauth.TokenRequest{
		Repositories: repositories,
		Permissions:  permissions,
	}
	accessToken, err := installation.AccessToken(ctx, &tokenRequest)
	if err != nil {
		return "", fmt.Errorf("error generating GitHub access token: %w", err)
	}
	return accessToken, nil
}

// RetrieveFileContents implements SourceSystem.
func (g *gitHubSourceSystem) RetrieveFileContents(ctx context.Context, org, repo, filePath, ref string) ([]byte, error) {
	token, err := g.MintAccessToken(ctx, org, repo, []string{repo}, map[string]string{"contents": "read"})
	if err != nil {
		return nil, fmt.Errorf("error minting access token for GitHub: %w", err)
	}
	client := github.NewClient(nil).WithAuthToken(token)
	if g.baseURL != "" {
		client, err = client.WithEnterpriseURLs(g.baseURL, g.baseURL)
		if err != nil {
			return nil, fmt.Errorf("error creating GitHub client: %w", err)
		}
	}
	fileContents, _, resp, err := client.Repositories.GetContents(ctx, org, repo, filePath, &github.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		} else {
			return nil, fmt.Errorf("error reading configuration file @ %s/%s/%s: %w", org, repo, filePath, err)
		}
	}
	if fileContents != nil {
		contents, err := fileContents.GetContent()
		if err != nil {
			return nil, fmt.Errorf("error reading configuration file contents @ %s/%s/%s: %w", org, repo, filePath, err)
		}
		return []byte(contents), nil
	}
	return nil, nil
}

// BaseURL implements SourceSystem.
func (g *gitHubSourceSystem) BaseURL() string {
	return "https://github.com"
}
