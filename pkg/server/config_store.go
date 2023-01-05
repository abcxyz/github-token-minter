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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// MemoryStore is an implementation of the ConfigReader interface
// which stores its configuration in a map that is preloaded on
// startup.
type MemoryStore struct {
	store map[string]*repositoryConfig
}

func loadStore(configLocation string) (map[string]*repositoryConfig, error) {
	store := map[string]*repositoryConfig{}
	// Get the list of subdirectories in the config location. Each one represents
	// a GitHub organization
	dirs, err := os.ReadDir(configLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration directory %s: %w", configLocation, err)
	}
	// Loop over each top level directory / "organization" and read config files
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		dname := dir.Name()
		files, err := os.ReadDir(filepath.Join(configLocation, dname))
		if err != nil {
			return nil, fmt.Errorf("failed to read directory %s/%s: %w", configLocation, dname, err)
		}
		// Loop over each file in the "organization" directory looking for repository configurations
		for _, f := range files {
			fname := f.Name()
			if f.IsDir() || !(strings.HasSuffix(fname, ".yaml") || strings.HasSuffix(fname, ".yml")) {
				continue
			}
			name := filepath.Join(configLocation, dname, fname)
			// Parse the configuration file and build the in memory representation
			id := strings.Join([]string{dname, strings.Split(fname, ".")[0]}, "/")
			content, err := parseFile(name)
			if err != nil {
				return nil, fmt.Errorf("error parsing config file %s: %w", name, err)
			}
			store[id] = content
		}
	}
	return store, nil
}

// NewInMemoryStore creates a ConfigReader implementation that stores
// the configuration objects in memory. All configurations are loaded once
// on creation.
func NewInMemoryStore(configLocation string) (*MemoryStore, error) {
	store, err := loadStore(configLocation)
	if err != nil {
		return nil, fmt.Errorf("error loading configuration data cache %w", err)
	}
	return &MemoryStore{store: store}, nil
}

// Read retrieves the RepositoryConfig object for a given repository
// e.g. abcxyz/somerepo.
func (m *MemoryStore) Read(repoKey string) (*repositoryConfig, error) {
	if val, ok := m.store[repoKey]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("repository configuration not found for '%s'", repoKey)
}

func parseFile(name string) (*repositoryConfig, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("error reading content from file: %w", err)
	}

	var content repositoryConfig
	if err := yaml.Unmarshal(data, &content); err != nil {
		return nil, fmt.Errorf("error parsing yaml document: %w", err)
	}
	return &content, nil
}
