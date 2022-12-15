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

// Package config manages the loading of repository config information
// that is stored as files in the file system. The files are parsed
// and loaded into memory.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ConfigStore is an interface that represents a collection of RepositoryConfigs
type ConfigStore interface {
	ConfigFor(repoKey string) (*RepositoryConfig, error)
}

type memoryStore struct {
	store map[string]*RepositoryConfig
}

func loadStore(configLocation string) (map[string]*RepositoryConfig, error) {
	store := map[string]*RepositoryConfig{}
	err := filepath.Walk(configLocation, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Ignore directories or files that don't end in .yaml|.yml
		if info.IsDir() || !(strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		// Parse the configuration file and build the in memory representation
		content, err := parse(file)
		if err != nil {
			return err
		}
		// Treat the last two parts of the path as the repository id e.g. abcxyz/breakglass.yaml = abcxyz/breakglass
		parts := strings.Split(path, "/")
		if len(parts) > 2 {
			parts = parts[len(parts)-2:]
		}
		parts[len(parts)-1] = strings.Split(parts[len(parts)-1], ".")[0]
		id := strings.Join(parts, "/")
		store[id] = content

		return nil
	})
	return store, err
}

// NewInMemoryStore creates a ConfigStore implementation that stores
// the configuration objects in memory. All configurations are loaded once
// on creation.
func NewInMemoryStore(configLocation string) (ConfigStore, error) {
	store, err := loadStore(configLocation)
	if err != nil {
		return nil, fmt.Errorf("error loading configuration data cache %w", err)
	}
	return &memoryStore{store: store}, nil
}

// ConfigFor retrieves the RepositoryConfig object for a given repository
// e.g. abcxyz/somerepo.
func (m *memoryStore) ConfigFor(repoKey string) (*RepositoryConfig, error) {
	if val, ok := m.store[repoKey]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("repository configuration not found for '%s'", repoKey)
}
