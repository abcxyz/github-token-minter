// Copyright 2024 The Authors (see AUTHORS file)
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

package config

import (
	"fmt"

	"github.com/google/cel-go/cel"
)

type v1Document []*v1Match

type v1Match struct {
	If           string            `yaml:"if" json:"if"`
	Repositories []string          `yaml:"repositories" json:"repositories"`
	Permissions  map[string]string `yaml:"permissions" json:"permissions"`
	Program      cel.Program       `yaml:"-" json:"-"`
}

func NewConfigFromV1(cv1 v1Document) Config {
	scopes := make(map[string]*Scope)
	for idx, m := range cv1 {
		scopes[fmt.Sprintf("default_%08d", idx)] = m.asScope()
	}
	return Config{
		Version: configVersionV1,
		Rule: &Rule{
			If: "true",
		},
		Scopes: scopes,
	}
}

func (m *v1Match) asScope() *Scope {
	return &Scope{
		Rule: &Rule{
			If: m.If,
		},
		Permissions:  m.Permissions,
		Repositories: m.Repositories,
	}
}
