// Copyright 2023 The Authors (see AUTHORS file)
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
	"testing"

	"github.com/abcxyz/pkg/testutil"
)

func TestValidatePermissions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		allowed   map[string]string
		requested map[string]string
		expErrMsg string
	}{
		{
			name:      "success",
			allowed:   map[string]string{"issues": "write"},
			requested: map[string]string{"issues": "write"},
		}, {
			name:      "request lesser permission",
			allowed:   map[string]string{"issues": "write"},
			requested: map[string]string{"issues": "read"},
		}, {
			name:      "request permission not authorized",
			allowed:   map[string]string{},
			requested: map[string]string{"issues": "read"},
			expErrMsg: `requested permission "issues" is not authorized`,
		}, {
			name:      "request multiple permissions success",
			allowed:   map[string]string{"issues": "read", "pull_requests": "write"},
			requested: map[string]string{"issues": "read", "pull_requests": "write"},
		}, {
			name:      "request multiple permissions with lesser",
			allowed:   map[string]string{"issues": "read", "pull_requests": "write"},
			requested: map[string]string{"issues": "read", "pull_requests": "read"},
		}, {
			name:      "request multiple permissions with failure",
			allowed:   map[string]string{"issues": "read", "pull_requests": "write"},
			requested: map[string]string{"issues": "read", "pull_requests": "write", "workflows": "read"},
			expErrMsg: `requested permission "workflows" is not authorized`,
		}, {
			name:      "request greater permission",
			allowed:   map[string]string{"issues": "read"},
			requested: map[string]string{"issues": "write"},
			expErrMsg: `requested permission level "write" for permission "issues" is not authorized`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validatePermissions(tc.allowed, tc.requested)
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Error(msg)
			}
		})
	}
}
