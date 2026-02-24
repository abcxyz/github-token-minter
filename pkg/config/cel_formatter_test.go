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

package config

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/go-cmp/cmp"
)

func TestFormatEvalDetails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		expr string
		env  map[string]any
		want string
	}{
		{
			name: "simple match",
			expr: "a == 'b'",
			env:  map[string]any{"a": "b"},
			want: `[+] EQUALS -> true
├── [v] Ident 'a' -> b
└── [v] Lit 'b' -> b
`,
		},
		{
			name: "simple mismatch",
			expr: "a == 'b'",
			env:  map[string]any{"a": "c"},
			want: `[x] EQUALS -> false
├── [v] Ident 'a' -> c
└── [v] Lit 'b' -> b
`,
		},
		{
			name: "logical AND success",
			expr: "a == 'b' && c == 'd'",
			env:  map[string]any{"a": "b", "c": "d"},
			want: `[+] AND -> true
├── [+] EQUALS -> true
│   ├── [v] Ident 'a' -> b
│   └── [v] Lit 'b' -> b
└── [+] EQUALS -> true
    ├── [v] Ident 'c' -> d
    └── [v] Lit 'd' -> d
`,
		},
		{
			name: "logical AND failure first",
			expr: "a == 'b' && c == 'd'",
			env:  map[string]any{"a": "wrong", "c": "d"},
			want: `[x] AND -> false
├── [x] EQUALS -> false
│   ├── [v] Ident 'a' -> wrong
│   └── [v] Lit 'b' -> b
└── [+] EQUALS -> true
    ├── [v] Ident 'c' -> d
    └── [v] Lit 'd' -> d
`,
		},
		{
			name: "logical OR success first",
			expr: "a == 'b' || c == 'd'",
			env:  map[string]any{"a": "b", "c": "wrong"},
			want: `[+] OR -> true
├── [+] EQUALS -> true
│   ├── [v] Ident 'a' -> b
│   └── [v] Lit 'b' -> b
└── [x] EQUALS -> false
    ├── [v] Ident 'c' -> wrong
    └── [v] Lit 'd' -> d
`,
		},
		{
			name: "logical OR failure both",
			expr: "a == 'b' || c == 'd'",
			env:  map[string]any{"a": "wrong", "c": "wrong"},
			want: `[x] OR -> false
├── [x] EQUALS -> false
│   ├── [v] Ident 'a' -> wrong
│   └── [v] Lit 'b' -> b
└── [x] EQUALS -> false
    ├── [v] Ident 'c' -> wrong
    └── [v] Lit 'd' -> d
`,
		},
		{
			name: "nested boolean logic",
			expr: "(a == 'b' || a == 'c') && d == 'e'",
			env:  map[string]any{"a": "c", "d": "e"},
			want: `[+] AND -> true
├── [+] OR -> true
│   ├── [x] EQUALS -> false
│   │   ├── [v] Ident 'a' -> c
│   │   └── [v] Lit 'b' -> b
│   └── [+] EQUALS -> true
│       ├── [v] Ident 'a' -> c
│       └── [v] Lit 'c' -> c
└── [+] EQUALS -> true
    ├── [v] Ident 'd' -> e
    └── [v] Lit 'e' -> e
`,
		},
		{
			name: "NOT operator",
			expr: "!a",
			env:  map[string]any{"a": false},
			want: `[+] NOT -> true
└── [x] Ident 'a' -> false
`,
		},
		{
			name: "nested select",
			expr: "msg.field == 'val'",
			env:  map[string]any{"msg": map[string]string{"field": "val"}},
			want: `[+] EQUALS -> true
├── [v] Select 'msg.field' -> val
└── [v] Lit 'val' -> val
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create CEL environment
			env, err := cel.NewEnv(
				cel.Variable("a", cel.AnyType),
				cel.Variable("c", cel.AnyType),
				cel.Variable("d", cel.AnyType),
				cel.Variable("e", cel.AnyType),
				cel.Variable("msg", cel.AnyType),
			)
			if err != nil {
				t.Fatalf("cel.NewEnv failed: %v", err)
			}

			// Compile expression
			ast, iss := env.Compile(tc.expr)
			if iss.Err() != nil {
				t.Fatalf("env.Compile failed: %v", iss.Err())
			}

			// Create program with exhausted eval to get details
			prg, err := env.Program(ast, cel.EvalOptions(cel.OptExhaustiveEval))
			if err != nil {
				t.Fatalf("env.Program failed: %v", err)
			}

			// Evaluate
			_, details, err := prg.Eval(tc.env)
			if err != nil {
				t.Fatalf("prg.Eval failed: %v", err)
			}

			// Format details
			got := formatEvalDetails(ast, details)

			// Compare normal output
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("formatEvalDetails() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
