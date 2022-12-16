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

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type memoryStore struct {
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
		files, err := os.ReadDir(fmt.Sprintf("%s/%s", configLocation, dname))
		if err != nil {
			return nil, fmt.Errorf("failed to read directory %s/%s: %w", configLocation, dname, err)
		}
		// Loop over each file in the "organization" directory looking for repository configurations
		for _, f := range files {
			fname := f.Name()
			if f.IsDir() || !(strings.HasSuffix(fname, ".yaml") || strings.HasSuffix(fname, ".yml")) {
				continue
			}
			name := fmt.Sprintf("%s/%s/%s", configLocation, dname, fname)
			file, err := os.Open(name)
			if err != nil {
				return nil, fmt.Errorf("error reading config file %s: %w", name, err)
			}
			defer file.Close()
			// Parse the configuration file and build the in memory representation
			content, err := parse(file)
			if err != nil {
				return nil, fmt.Errorf("error parsing config file %s: %w", name, err)
			}
			id := strings.Join([]string{dname, strings.Split(fname, ".")[0]}, "/")
			store[id] = content
		}
	}
	return store, nil
}

// newInMemoryStore creates a ConfigStore implementation that stores
// the configuration objects in memory. All configurations are loaded once
// on creation.
func newInMemoryStore(configLocation string) (configStore, error) {
	store, err := loadStore(configLocation)
	if err != nil {
		return nil, fmt.Errorf("error loading configuration data cache %w", err)
	}
	return &memoryStore{store: store}, nil
}

// ConfigFor retrieves the RepositoryConfig object for a given repository
// e.g. abcxyz/somerepo.
func (m *memoryStore) ConfigFor(repoKey string) (*repositoryConfig, error) {
	if val, ok := m.store[repoKey]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("repository configuration not found for '%s'", repoKey)
}

func parse(content io.Reader) (*repositoryConfig, error) {
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(content); err != nil {
		return nil, fmt.Errorf("error reading content from buffer: %w", err)
	}

	var config repositoryConfig
	if err := yaml.Unmarshal(buf.Bytes(), &config); err != nil {
		return nil, fmt.Errorf("error parsing yaml document: %w", err)
	}
	return &config, nil
}
