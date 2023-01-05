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

// RepositoryConfig defines a set of configurations for a GitHub repository.
type RepositoryConfig []Config

// Config defines a conditional configuration for a set of permissions.
type Config struct {
	If           string            `yaml:"if"`
	Repositories []string          `yaml:"repositories"`
	Permissions  map[string]string `yaml:"permissions"`
}

// ConfigReader is an interface that will produce a repository config
// for a given repository name.
type ConfigReader interface {
	Read(repoKey string) (*RepositoryConfig, error)
}
