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

func TestTokenClaimString(t *testing.T) {
	t.Parallel()

	token, _ := jwt.NewBuilder().
		Audience([]string{"https://github.com/abcxyz"}).
		Subject("https://token.actions.githubusercontent.com").
		Issuer("repo:abcxyz/test:ref:refs/heads/main").
		Claim("repository", "abcxyz/test").
		Claim("nonstring_type", 1245).
		Build()

	cases := []struct {
		name      string
		token     jwt.Token
		value     string
		required  bool
		want      string
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
			want:      "",
			expErr:    true,
			expErrMsg: `claim "test" not found`,
		},
		{
			name:      "required wrong type",
			token:     token,
			value:     "nonstring_type",
			required:  true,
			want:      "",
			expErr:    true,
			expErrMsg: `claim "nonstring_type" not the correct type want=string, got=int`,
		},
		{
			name:      "missing optional",
			token:     token,
			value:     "test",
			required:  false,
			want:      "",
			expErr:    false,
			expErrMsg: "",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tokenClaimString(tc.token, tc.value, tc.required)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}
		})
	}
}
