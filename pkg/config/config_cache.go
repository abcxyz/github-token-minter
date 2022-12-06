package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ConfigCache interface {
	ConfigFor(repoKey string) (*RepositoryConfig, error)
}

type memoryConfigCache struct {
	store map[string]*RepositoryConfig
}

func buildCacheStore(configLocation string) (map[string]*RepositoryConfig, error) {
	parser := NewConfigParser()
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
		content, err := parser.parse(file)
		if err != nil {
			return err
		}
		_ = content // remove after update
		//TODO(@bradegler) - Update to use last 2 parts of file path
		//store[content.Id] = content

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

func (m *memoryConfigCache) ConfigFor(repoKey string) (*RepositoryConfig, error) {
	if val, ok := m.store[repoKey]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("repository configuration not found for '%s'", repoKey)
}
