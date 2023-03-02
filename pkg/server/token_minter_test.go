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
	"github.com/google/go-cmp/cmp"
)

func TestValidateRepositories(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		allow     []string
		request   []string
		want      []string
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "empty allow single request",
			allow:     []string{},
			request:   []string{"test1"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "test1" is not in the allow list`,
		},
		{
			name:      "single allow single request - match",
			allow:     []string{"test1"},
			request:   []string{"test1"},
			want:      []string{"test1"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow single request - match",
			allow:     []string{"test1", "test2"},
			request:   []string{"test1"},
			want:      []string{"test1"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow multiple request - match",
			allow:     []string{"test1", "test2"},
			request:   []string{"test1", "test2"},
			want:      []string{"test1", "test2"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow multiple request - not first - match",
			allow:     []string{"test1", "test2", "test3", "test4"},
			request:   []string{"test4", "test2"},
			want:      []string{"test4", "test2"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "single allow single request - no match",
			allow:     []string{"test1"},
			request:   []string{"test2"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "test2" is not in the allow list`,
		},
		{
			name:      "multiple allow single request - no match",
			allow:     []string{"test1", "test2", "test3"},
			request:   []string{"test4"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "test4" is not in the allow list`,
		},
		{
			name:      "multiple allow multiple request - no match",
			allow:     []string{"test1", "test2", "test3"},
			request:   []string{"test4", "test5"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "test4" is not in the allow list`,
		},
		{
			name:      "single allow * request - match",
			allow:     []string{"test1", "test2", "test3"},
			request:   []string{"*"},
			want:      []string{"test1", "test2", "test3"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "empty allow * request",
			allow:     []string{},
			request:   []string{"*"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "*" is not in the allow list`,
		},
		{
			name:      "empty allow prefix-* request",
			allow:     []string{},
			request:   []string{"prefix-*"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "prefix-*" is not in the allow list`,
		},
		{
			name:      "single allow prefix-* request - match",
			allow:     []string{"test1"},
			request:   []string{"test*"},
			want:      []string{"test1"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow prefix-* request - all match",
			allow:     []string{"test1", "test2"},
			request:   []string{"test*"},
			want:      []string{"test1", "test2"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "multiple allow prefix-* request - partial match",
			allow:     []string{"test1", "test2", "nottest"},
			request:   []string{"test*"},
			want:      []string{"test1", "test2"},
			expErr:    false,
			expErrMsg: "",
		},
		{
			name:      "single allow prefix-* request - no match",
			allow:     []string{"test1"},
			request:   []string{"prefix-*"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "prefix-*" is not in the allow list`,
		},
		{
			name:      "multiple allow prefix-* request - no match",
			allow:     []string{"test1", "test2"},
			request:   []string{"prefix-*"},
			want:      nil,
			expErr:    true,
			expErrMsg: `requested repository "prefix-*" is not in the allow list`,
		},
	}
	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := validateRepositories(tc.allow, tc.request)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}
			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatalf(msg)
			}
			if !tc.expErr && got == nil {
				t.Errorf("program nil without error")
			}
		})
	}
}
