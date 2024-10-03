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

	"github.com/abcxyz/github-token-minter/pkg/server"
	"github.com/abcxyz/github-token-minter/pkg/version"
	"github.com/abcxyz/pkg/cli"
	"github.com/abcxyz/pkg/logging"
)

var _ cli.Command = (*ServerCommand)(nil)

type ServerCommand struct {
	cli.BaseCommand
	cfg *server.Config

	// testFlagSetOpts is only used for testing.
	testFlagSetOpts []cli.Option
}

func (c *ServerCommand) Desc() string {
	return ``
}

func (c *ServerCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]
       Execute the minty configuration validator 
`
}

func (c *ServerCommand) Flags() *cli.FlagSet {
	c.cfg = &server.Config{}
	set := cli.NewFlagSet(c.testFlagSetOpts...)
	return c.cfg.ToFlags(set)
}

func (c *ServerCommand) Run(ctx context.Context, args []string) error {
	f := c.Flags()
	if err := f.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %w", err)
	}
	args = f.Args()
	if len(args) > 0 {
		return fmt.Errorf("unexpected arguments: %q", args)
	}

	logger := logging.FromContext(ctx)
	logger.InfoContext(ctx, "running job",
		"name", version.Name,
		"commit", version.Commit,
		"version", version.Version)

	if err := c.cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	logger.InfoContext(ctx, "loaded configuration", "config", c.cfg)

	if err := server.Run(ctx, c.cfg); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	return nil
}
