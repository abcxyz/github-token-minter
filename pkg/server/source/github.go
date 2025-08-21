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
	"strings"

	"github.com/google/go-github/v64/github"

	"github.com/abcxyz/pkg/githubauth"
)

// GitHubAppConfig is a struct that contains the identifier for a GitHub App
// and a Signer that can be used to sign requests.
type GitHubAppConfig struct {
	AppID  string
	Signer crypto.Signer
}

// gitHubSourceSystem is a SourceSystem implementation that is backed by GitHub.
type gitHubSourceSystem struct {
	apps    []*githubauth.App
	baseURL string
}

// NewGitHubSourceSystem creates a representation of a GitHub system. This includes
// information about what the base url and any of the Apps that can be used by the
// system.
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
		installation, err = app.InstallationForOrg(ctx, org)
		if err != nil {
			errs = append(errs, err)
		} else {
			// Accept the first installation that provides a token
			// @TODO(bradegler) - resolve how to handle multiple GitHub apps
			break
		}
	}
	if len(errs) != 0 {
		return "", fmt.Errorf("errors retrieving GitHub installation: %w", errors.Join(errs...))
	}
	if repositories == nil {
		allRepoRequest := &githubauth.TokenRequestAllRepos{Permissions: permissions}

		accessToken, err := installation.AccessTokenAllRepos(ctx, allRepoRequest)
		if err != nil {
			if strings.Contains(err.Error(), "invalid http response status (expected 404 to be 201):") ||
				strings.Contains(err.Error(), "invalid http response status (expected 422 to be 201):") {
				return "", nil
			}
			return "", fmt.Errorf("error generating GitHub access token for all repositories: %w", err)
		}
		return accessToken, nil
	}
	tokenRequest := githubauth.TokenRequest{
		Repositories: repositories,
		Permissions:  permissions,
	}
	accessToken, err := installation.AccessToken(ctx, &tokenRequest)
	if err != nil {
		if strings.Contains(err.Error(), "invalid http response status (expected 404 to be 201):") ||
			strings.Contains(err.Error(), "invalid http response status (expected 422 to be 201):") {
			return "", nil
		}
		return "", fmt.Errorf("error generating GitHub access token for named repositories: %w", err)
	}
	return accessToken, nil
}

// RetrieveFileContents implements SourceSystem.
func (g *gitHubSourceSystem) RetrieveFileContents(ctx context.Context, org, repo, filePath, ref string) ([]byte, error) {
	token, err := g.MintAccessToken(ctx, org, repo, []string{repo}, map[string]string{"contents": "read"})
	if err != nil {
		return nil, fmt.Errorf("error minting access token for GitHub: %w", err)
	}

	// MintAccessToken will return an empty string if the repository doesn't exist
	// treat this the same way we handle "not found" conditions.
	if token == "" {
		return nil, nil
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
		// 404 if the file doesn't exist
		// 422 if the whole repo is missing
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnprocessableEntity {
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
