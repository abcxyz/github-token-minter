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

package source

import "context"

type System interface {
	// MintAccessToken generates a new access token on behalf of the org/rep for the given repositories with
	// the specified permissions.
	MintAccessToken(ctx context.Context, org, repo string, repositories []string, permissions map[string]string) (string, error)

	// RetrieveFileContents gets the contents of the file at filePath with the specified ref
	// from the org/repo.
	RetrieveFileContents(ctx context.Context, org, repo, filePath, ref string) ([]byte, error)

	// BaseURL gets the base url for the system.
	BaseURL() string
}
