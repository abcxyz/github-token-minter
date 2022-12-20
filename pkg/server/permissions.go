// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"

	"github.com/abcxyz/pkg/logging"
	"github.com/google/cel-go/cel"
)

const assertionKey string = "assertion"

// permissionsForToken evaluates a RepositoryConfig using attributes provided in an OIDC token
// to determine the level of permissions that should be requested from GitHub.
func permissionsForToken(ctx context.Context, rc *repositoryConfig, token map[string]interface{}) (*config, error) {
	logger := logging.FromContext(ctx)

	env, err := cel.NewEnv(cel.Variable(assertionKey, cel.DynType))
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	for _, p := range *rc {
		ast, iss := env.Compile(p.If)
		if iss.Err() != nil {
			return nil, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
		}

		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("failed to create CEL program: %w", err)
		}

		out, _, err := prg.Eval(map[string]interface{}{
			assertionKey: token,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate CEL expression: %w", err)
		}

		if v, ok := (out.Value()).(bool); v && ok {
			logger.Debugf("found token permissions")
			return &p, nil
		}
	}

	return nil, fmt.Errorf("no permissions found")
}
