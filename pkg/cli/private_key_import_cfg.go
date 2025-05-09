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
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/sethvargo/go-retry"

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
	return `import the github private key to cloud KMS`
}

func (c *PrivateKeyImportCommand) Help() string {
	return `
Usage: {{ COMMAND }} [options]
       Execute the Private Key Import Command 
Import github private key to cloud KMS via file:

      {{ COMMAND }} -project-id=<PROJECT_ID> -location=<LOCATION> -key-ring=<KEY_RING> -key=<KEY> -import-job-prefix=<IMPORT_JOB_PREFIX> -private-key=@<PRIVATE_KEY_FILE_PATH>

Import github private key to cloud KMS via stdin:

      {{ COMMAND }} -project-id=<PROJECT_ID> -location=<LOCATION> -key-ring=<KEY_RING> -key=<KEY> -import-job-prefix=<IMPORT_JOB_PREFIX> -private-key=-<STD_IN_PRIVATE_KEY_CONTENT>
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
	gotKeyRing, err := keyServer.GetOrCreateKeyRing(ctx, c.cfg.ProjectID, c.cfg.Location, c.cfg.KeyRing)
	if err != nil {
		return fmt.Errorf("encountered error when creating/getting key ring: %w", err)
	}
	logger.DebugContext(ctx, "Got key ring successfully\n", "key_ring", gotKeyRing.GetName())
	gotKey, err := keyServer.GetOrCreateKey(ctx, c.cfg.ProjectID, c.cfg.Location, c.cfg.KeyRing, c.cfg.Key)
	if err != nil {
		return fmt.Errorf("encountered error when creating/getting key: %w", err)
	}
	logger.DebugContext(ctx, "Got key successfully", "key_ring", gotKey.GetName())
	gotImportJob, err := keyServer.GetOrCreateImportJob(ctx, c.cfg.ProjectID, c.cfg.Location, c.cfg.KeyRing, c.cfg.ImportJobPrefix)
	if err != nil {
		return fmt.Errorf("encountered error when creating/getting import job: %w", err)
	}
	logger.DebugContext(ctx, "Got import job successfully", "import_job", gotImportJob.GetName())

	if err := retry.Do(ctx, newBackoff(), func(ctx context.Context) error {
		importedJob, err := keyServer.GetImportJob(ctx, gotImportJob.GetName())
		if err != nil {
			return fmt.Errorf("encountered error when checking state of import job: %w", err)
		}
		if importedJob.GetState() != kmspb.ImportJob_ACTIVE {
			return retry.RetryableError(fmt.Errorf("import job is not in active stage"))
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to check import job state to be active: %w", err)
	}
	createdKeyVersion, err := keyServer.ImportManuallyWrappedKey(ctx, gotImportJob.GetName(), gotKey.GetName(), c.cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to import key version: %w", err)
	}
	logger.DebugContext(ctx, "Got key version imported", "key_version", createdKeyVersion.GetName())

	if err := retry.Do(ctx, newBackoff(), func(ctx context.Context) error {
		importedKeyVersion, err := keyServer.GetKeyVersion(ctx, createdKeyVersion.GetName())
		if err != nil {
			return fmt.Errorf("encountered error when querying imported key version %q: %w", createdKeyVersion.GetName(), err)
		}
		if importedKeyVersion.GetState() != kmspb.CryptoKeyVersion_ENABLED {
			return retry.RetryableError(fmt.Errorf("import key version is not in enabled stage"))
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to check key version state to be enabled: %w", err)
	}

	fmt.Printf("key version imported (%q) is ready to use\n",
		createdKeyVersion.GetName())

	defer func() {
		if err := closer.Close(); err != nil {
			logger.ErrorContext(ctx, "failed to close", "error", err)
		}
	}()
	return nil
}

func newBackoff() retry.Backoff {
	return retry.WithMaxRetries(5, retry.NewConstant(1*time.Second))
}
