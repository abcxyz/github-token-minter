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

package server

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/abcxyz/pkg/testutil"
)

func TestTokenClaim(t *testing.T) {
	t.Parallel()

	token, _ := jwt.NewBuilder().
		Audience([]string{"https://github.com/abcxyz"}).
		Subject("https://token.actions.githubusercontent.com").
		Issuer("repo:abcxyz/test:ref:refs/heads/main").
		Claim("repository", "abcxyz/test").
		Claim("int_claim", 1245).
		Claim("bool_claim", true).
		Build()

	cases := []struct {
		name      string
		token     jwt.Token
		value     string
		required  bool
		want      any
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "success",
			token:     token,
			value:     "repository",
			required:  true,
			want:      "abcxyz/test",
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "missing required",
			token:     token,
			value:     "test",
			required:  true,
			expErr:    true,
			expErrMsg: `claim "test" not found`,
		},
		{
			name:      "missing optional",
			token:     token,
			value:     "test",
			required:  false,
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "success_bool",
			token:     token,
			value:     "bool_claim",
			required:  true,
			want:      true,
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "success_int",
			token:     token,
			value:     "int_claim",
			required:  true,
			want:      1245,
			expErr:    false,
			expErrMsg: "",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			runCase(t, tc.token, tc.value, tc.required, tc.want, tc.expErrMsg)
		})
	}
}

func runCase[T any](t *testing.T, token jwt.Token, value string, required bool, want T, expErrMsg string) {
	t.Helper()

	got, err := tokenClaim[T](token, value, required)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want, +got):\n%s", diff)
	}
	if msg := testutil.DiffErrString(err, expErrMsg); msg != "" {
		t.Fatalf(msg)
	}
}
