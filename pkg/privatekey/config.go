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

package privatekey

import (
	"errors"
	"fmt"

	"github.com/abcxyz/pkg/cli"
)

// Config defines the set of environment variables required
// for running the private key job.
type Config struct {
	ProjectID  string
	Location   string
	KeyRing    string
	Key        string
	PrivateKey string
}

// Validate validates the config after load.
func (cfg *Config) Validate() (vErr error) {
	if cfg.ProjectID == "" {
		vErr = errors.Join(vErr, fmt.Errorf("PROJECT_ID is required"))
	}

	if cfg.Location == "" {
		vErr = errors.Join(vErr, fmt.Errorf("LOCATION is required"))
	}

	if cfg.KeyRing == "" {
		vErr = errors.Join(vErr, fmt.Errorf("KEY_RING is required"))
	}

	if cfg.Key == "" {
		vErr = errors.Join(vErr, fmt.Errorf("KEY is required"))
	}

	if cfg.PrivateKey == "" {
		vErr = errors.Join(vErr, fmt.Errorf("PRIVATE_KEY is required"))
	}
	return
}

// ToFlags binds the config to the [cli.FlagSet] and returns it.
func (cfg *Config) ToFlags(set *cli.FlagSet) *cli.FlagSet {
	f := set.NewSection("COMMON JOB OPTIONS")

	f.StringVar(&cli.StringVar{
		Name:   "project-id",
		Target: &cfg.ProjectID,
		EnvVar: "PROJECT_ID",
		Usage:  `The gcp project id.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "location",
		Target: &cfg.Location,
		EnvVar: "LOCATION",
		Usage:  `The Cloud KMS location of the key ring.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "key-ring",
		Target: &cfg.KeyRing,
		EnvVar: "KEY_RING",
		Usage:  `the name of the key ring that contains the key.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "key",
		Target: &cfg.Key,
		EnvVar: "KEY",
		Usage:  `the name of the key.`,
	})

	f.StringVar(&cli.StringVar{
		Name:   "private-key",
		Target: &cfg.PrivateKey,
		Usage:  `The private key file to import. By default accept a filepath, and if input is exactly "-", read the value from stdin instead`,
	})

	return set
}
