// Copyright 2022 Google LLC
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

// repositoryConfig defines a set of configurations for a GitHub repository
type repositoryConfig []config

// config defines a conditional configuration for a set of permissions
type config struct {
	If           string            `yaml:"if"`
	Repositories []string          `yaml:"repositories"`
	Permissions  map[string]string `yaml:"permissions"`
}

// configStore is an interface that represents a collection of RepositoryConfigs
type configStore interface {
	ConfigFor(repoKey string) (*repositoryConfig, error)
}