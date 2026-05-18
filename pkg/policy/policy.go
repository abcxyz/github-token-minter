// Copyright 2026 The Authors (see AUTHORS file)
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

package policy

import (
	"context"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Evaluator wraps a prepared OPA query for policy evaluation.
type Evaluator struct {
	query rego.PreparedEvalQuery
}

// LoadPolicies loads all Rego policies from the specified directory
// and prepares a query for `data.minty.policy.deny`.
func LoadPolicies(dir string) (*Evaluator, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("failed to stat policy dir: %w", err)
	}

	ctx := context.Background()

	r := rego.New(
		rego.Query("data.minty.policy.deny"),
		rego.Load([]string{dir}, nil),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query: %w", err)
	}

	return &Evaluator{query: pq}, nil
}

// Evaluate runs the prepared policy query against the provided input.
// It returns a list of denial messages. If the list is empty, the request is allowed.
func (e *Evaluator) Evaluate(ctx context.Context, input any) ([]string, error) {
	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, nil
	}

	val := results[0].Expressions[0].Value

	list, ok := val.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected result type from policy: expected []any, got %T", val)
	}

	denies := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected item type in deny list: expected string, got %T", item)
		}
		denies = append(denies, s)
	}

	return denies, nil
}
