// Copyright 2025 The Authors (see AUTHORS file)
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

	"github.com/abcxyz/pkg/logging"
)

func TestCreateAppConfigs(t *testing.T) {
	t.Parallel()

	ctx := logging.WithLogger(t.Context(), logging.TestLogger(t))

	cases := []struct {
		name               string
		sourcesSystemAuths []string
	}{
		{
			name:               "missing configurations",
			sourcesSystemAuths: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &Config{SourceSystemAuth: tc.sourcesSystemAuths}

			createAppConfigs(ctx, cfg)
		})
	}
}
