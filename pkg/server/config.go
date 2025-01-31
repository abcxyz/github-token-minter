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
	"fmt"
	"time"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/pkg/cli"
)

type Config struct {
	Port       string
	AppID      string
	PrivateKey string

	// GitHubAPIBaseURL is the base URL for the GitHub installation. It should
	// include the protocol (https://) and no trailing slashes.
	GitHubAPIBaseURL string

	ConfigDir          string
	RepoConfigPath     string
	OrgConfigRepo      string
	OrgConfigPath      string
	Ref                string
	ConfigCacheSeconds string

	JWKSCacheDuration time.Duration
	IssuerAllowlist   []string
}

// Validate validates the artifacts config after load.
func (cfg *Config) Validate() error {
	if cfg.AppID == "" {
		return fmt.Errorf("GITHUB_APP_ID is required")
	}
	if cfg.PrivateKey == "" {
		return fmt.Errorf("GITHUB_PRIVATE_KEY is required")
	}
	if cfg.ConfigCacheSeconds == "" {
		cfg.ConfigCacheSeconds = "900"
	}

	if cfg.OrgConfigRepo == "" {
		cfg.OrgConfigRepo = ".minty"
	}
	if cfg.OrgConfigPath == "" {
		cfg.OrgConfigPath = "minty.yaml"
	}
	if cfg.RepoConfigPath == "" {
		cfg.RepoConfigPath = ".github/minty.yaml"
	}
	if cfg.Ref == "" {
		cfg.Ref = "main"
	}

	return nil
}

// ToFlags binds the config to the [cli.FlagSet] and returns it.
func (cfg *Config) ToFlags(set *cli.FlagSet) *cli.FlagSet {
	f := set.NewSection("COMMON JOB OPTIONS")

	f.StringVar(&cli.StringVar{
		Name:   "port",
		Target: &cfg.Port,
		EnvVar: "PORT",
		Usage:  `The port that this server runs as.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "github-app-id",
		Target: &cfg.AppID,
		EnvVar: "GITHUB_APP_ID",
		Usage:  `The ID of the GitHub App that this server runs as.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "github-private-key",
		Target: &cfg.PrivateKey,
		EnvVar: "GITHUB_PRIVATE_KEY",
		Usage:  `The private key of the GitHub App that this server runs as.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "github-api-base-url",
		Target: &cfg.GitHubAPIBaseURL,
		EnvVar: "GITHUB_API_BASE_URL",
		Usage:  `The base URL for the GitHub installation. It should include the protocol (https://) and no trailing slashes.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "config-dir",
		Target: &cfg.ConfigDir,
		EnvVar: "CONFIGS_DIR",
		Usage:  `The directory containing local configuration files.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "repo-config-path",
		Target: &cfg.RepoConfigPath,
		EnvVar: "REPO_CONFIG_PATH",
		Usage:  `The path to the minty configuration file in a repository.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "org-config-path",
		Target: &cfg.OrgConfigPath,
		EnvVar: "ORG_CONFIG_PATH",
		Usage:  `The path to the minty configuration file for an organization.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "org-config-repo",
		Target: &cfg.OrgConfigRepo,
		EnvVar: "ORG_CONFIG_REPO",
		Usage:  `The repository that contains the configuration file for an organization.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "ref",
		Target: &cfg.Ref,
		EnvVar: "REF",
		Usage:  `The ref (sha, branch, etc.) to look for configuration files at.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "config-cache-minutes",
		Target: &cfg.ConfigCacheSeconds,
		EnvVar: "CONFIG_CACHE_MINUTES",
		Usage:  `The number of minutes to cache configuration files before retrieving fresh ones. Defaults to 15 minutes.`,
	})

	f.DurationVar(&cli.DurationVar{
		Name:    "jwks-cache-duration",
		Target:  &cfg.JWKSCacheDuration,
		EnvVar:  "JWKS_CACHE_DURATION",
		Usage:   `The duration for which to cache the JWKS for an OIDC token issuer.`,
		Default: 4 * time.Hour,
	})

	f.StringSliceVar(&cli.StringSliceVar{
		Name:    "issuer-allowlist",
		Target:  &cfg.IssuerAllowlist,
		EnvVar:  "ISSUER_ALLOWLIST",
		Usage:   `The list of OIDC token issuers that GitHub Token Minter will accept. Format is a comma-separated list of URLs or the flag can be specified multiple times.`,
		Default: []string{config.GitHubIssuer, config.GoogleIssuer},
	})

	return set
}
