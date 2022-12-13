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
package config

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

type RepositoryConfig struct {
	Config []Config `yaml:"config"`
}

type Config struct {
	If           string            `yaml:"if"`
	Repositories []string          `yaml:"repositories"`
	Permissions  map[string]string `yaml:"permissions"`
}

// Parser represents a simple interface for parsing RepositoryConfig
// objects from a reader containing a YAML configuration file.
type Parser interface {
	parse(io.Reader) (*RepositoryConfig, error)
}

type configParser struct{}

func NewParser() Parser {
	return &configParser{}
}

func (p *configParser) parse(content io.Reader) (*RepositoryConfig, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(content)
	if err != nil {
		return nil, fmt.Errorf("error reading content from buffer: %w", err)
	}

	var config RepositoryConfig
	err = yaml.Unmarshal(buf.Bytes(), &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing yaml document: %w", err)
	}
	return &config, nil
}
