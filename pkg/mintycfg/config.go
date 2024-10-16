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

package mintycfg

import (
	"fmt"

	"github.com/abcxyz/pkg/cli"
)

// Config defines the set of environment variables required
// for running the artifact job.
type Config struct {
	MintyFile string
	Scope     string
	Token     string
}

// Validate validates the artifacts config after load.
func (cfg *Config) Validate() error {
	if cfg.MintyFile == "" {
		return fmt.Errorf("MINTY_FILE is required")
	}
	return nil
}

// ToFlags binds the config to the [cli.FlagSet] and returns it.
func (cfg *Config) ToFlags(set *cli.FlagSet) *cli.FlagSet {
	f := set.NewSection("COMMON JOB OPTIONS")

	f.StringVar(&cli.StringVar{
		Name:   "minty-file",
		Target: &cfg.MintyFile,
		EnvVar: "MINTY_FILE",
		Usage:  `The minty config file to inspect.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "scope",
		Target: &cfg.Scope,
		EnvVar: "SCOPE",
		Usage:  `The scope to test.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "token",
		Target: &cfg.Token,
		EnvVar: "token",
		Usage:  `The token to test with.`,
	})

	return set
}
