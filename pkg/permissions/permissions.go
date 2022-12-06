package permissions

import (
	"fmt"

	"github.com/abcxyz/minty/pkg/config"
	"github.com/google/cel-go/cel"
)

func GetPermissionsForToken(pc *config.PermissionsConfig, token map[string]interface{}) (*config.Permission, error) {
	env, err := cel.NewEnv(
		cel.Variable("jwt", cel.DynType),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	for _, p := range pc.Permissions {
		ast, iss := env.Compile(p.If)
		if iss.Err() != nil {
			return nil, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
		}

		prg, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("failed to create CEL program: %w", err)
		}

		out, _, err := prg.Eval(map[string]interface{}{
			"jwt": token,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate CEL expression: %w", err)
		}

		if (out.Value()).(bool) {
			return &p, nil
		}
	}

	return nil, fmt.Errorf("no permissions found")
}
