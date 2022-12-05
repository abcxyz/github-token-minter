package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ConfigCache interface {
	ConfigFor(repoKey string) (*PermissionsConfig, error)
}

type memoryConfigCache struct {
	store map[string]*PermissionsConfig
}

func buildCacheStore(configLocation string) (map[string]*PermissionsConfig, error) {
	parser := NewConfigParser()
	store := map[string]*PermissionsConfig{}
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
		content, err := parser.parse(file)
		if err != nil {
			return err
		}
		store[content.Id] = content

		return nil
	})
	return store, err
}

func NewMemoryConfigCache(configLocation string) (ConfigCache, error) {
	store, err := buildCacheStore(configLocation)
	if err != nil {
		return nil, fmt.Errorf("error loading configuration data cache %w", err)
	}
	return &memoryConfigCache{store: store}, nil
}

func (m *memoryConfigCache) ConfigFor(repoKey string) (*PermissionsConfig, error) {
	if val, ok := m.store[repoKey]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("repository configuration not found for '%s'", repoKey)
}
