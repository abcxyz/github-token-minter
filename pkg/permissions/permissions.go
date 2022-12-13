package permissions

import (
	"context"
	"fmt"

	"github.com/abcxyz/github-token-minter/pkg/config"
	"github.com/abcxyz/pkg/logging"
	"github.com/google/cel-go/cel"
)

const assertionKey string = "assertion"

func GetPermissionsForToken(ctx context.Context, rc *config.RepositoryConfig, token map[string]interface{}) (*config.Config, error) {
	logger := logging.FromContext(ctx)

	env, err := cel.NewEnv(
		cel.Variable(assertionKey, cel.DynType),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	for _, p := range rc.Config {
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
			logger.Infof("found token permissions")
			return &p, nil
		}
	}

	return nil, fmt.Errorf("no permissions found")
}
