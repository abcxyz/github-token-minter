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
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicies_NonExistentDir(t *testing.T) {
	t.Parallel()

	_, err := LoadPolicies("/non-existent-dir")
	if err == nil {
		t.Fatal("expected error loading from non-existent dir, got nil")
	}
}

func TestEvaluator_Evaluate_Deny(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	rego := `
package minty.policy
deny contains "not allowed" if {
    input.allowed == false
}
`
	err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(rego), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	eval, err := LoadPolicies(dir)
	if err != nil {
		t.Fatal(err)
	}

	input := map[string]any{"allowed": false}
	denies, err := eval.Evaluate(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}

	if len(denies) != 1 || denies[0] != "not allowed" {
		t.Errorf("expected [\"not allowed\"], got %v", denies)
	}
}
