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

package cli

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"

	"github.com/abcxyz/github-token-minter/pkg/privatekey"
	"github.com/abcxyz/github-token-minter/pkg/version"
	"github.com/abcxyz/pkg/cli"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/multicloser"
)

var _ cli.Command = (*PrivateKeyImportCommand)(nil)

type PrivateKeyImportCommand struct {
	cli.BaseCommand
	cfg *privatekey.Config
	// testFlagSetOpts is only used for testing.
	testFlagSetOpts []cli.Option
}

func (c *PrivateKeyImportCommand) Desc() string {
	return ``
}

func (c *PrivateKeyImportCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]
       Execute the Private Key Import Command 
`
}

func (c *PrivateKeyImportCommand) Flags() *cli.FlagSet {
	c.cfg = &privatekey.Config{}
	set := cli.NewFlagSet(c.testFlagSetOpts...)
	return c.cfg.ToFlags(set)
}

func (c *PrivateKeyImportCommand) Run(ctx context.Context, args []string) error {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}
	args = f.Args()
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %q", args)
	}

	logger := logging.FromContext(ctx)
	logger.DebugContext(ctx, "running job",
		"name", version.Name,
		"commit", version.Commit,
		"version", version.Version)

	if err := c.cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	logger.DebugContext(ctx, "loaded configuration", "config", c.cfg)

	var closer *multicloser.Closer
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to setup kms client: %w", err)
	}
	closer = multicloser.Append(closer, kmsClient.Close)

	keyServer, err := privatekey.NewKeyServer(ctx, kmsClient)
	if err != nil {
		return fmt.Errorf("failed to create key server: %w", err)
	}
	gotKeyRing, err := keyServer.CreateKeyRingIfNotExists(ctx, c.cfg.ProjectID, c.cfg.Location, c.cfg.KeyRing)
	if err != nil {
		return fmt.Errorf("encountered error when creating/getting key ring: %w", err)
	}
	logger.InfoContext(ctx, "Got key ring successfully", "key ring", gotKeyRing.GetName())
	// TODO Create key and import key version

	defer func() {
		if err := closer.Close(); err != nil {
			logger.ErrorContext(ctx, "failed to close", "error", err)
		}
	}()
	return nil
}
