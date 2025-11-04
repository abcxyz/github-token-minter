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

package minter

import (
	"fmt"

	"github.com/abcxyz/pkg/cli"
)

// Config defines the set of environment variables required
// for running the artifact job.
type Config struct {
	Request  string
	Token    string
	MintyURL string
}

// Validate validates the artifacts config after load.
func (cfg *Config) Validate() error {
	if cfg.Request == "" {
		return fmt.Errorf("REQUEST is required")
	}
	if cfg.Token == "" {
		return fmt.Errorf("TOKEN is required")
	}
	if cfg.MintyURL == "" {
		return fmt.Errorf("MINTY_URL is required")
	}

	return nil
}

// ToFlags binds the config to the [cli.FlagSet] and returns it.
func (cfg *Config) ToFlags(set *cli.FlagSet) *cli.FlagSet {
	f := set.NewSection("MINT JOB OPTIONS")

	f.StringVar(&cli.StringVar{
		Name:   "request",
		Target: &cfg.Request,
		EnvVar: "REQUEST",
		Usage:  `The token request to mint a token for.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "token",
		Target: &cfg.Token,
		EnvVar: "TOKEN",
		Usage:  `The OIDC token to exchange. This could be a GCP service account or GitHub token.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "mintyURL",
		Target: &cfg.MintyURL,
		EnvVar: "MINTY_URL",
		Usage:  `The URL of the minty server.`,
	})

	return set
}
