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
	"strings"
)

//go:generate stringer -type=Level -trimprefix=Level
type Level uint8

const (
	LevelInvalid Level = 1 << iota
	LevelRead
	LevelWrite
	LevelAdmin
)

// mapping of level names to an integer value for comparative purposes.
var levels = map[string]Level{
	strings.ToLower(LevelRead.String()):  LevelRead,
	strings.ToLower(LevelWrite.String()): LevelWrite,
	strings.ToLower(LevelAdmin.String()): LevelAdmin,
}

// mapping of level names to the Levels that are part of them.
var levelInheritence = map[string]Level{
	strings.ToLower(LevelRead.String()):  LevelRead,
	strings.ToLower(LevelWrite.String()): LevelWrite | LevelRead,
	strings.ToLower(LevelAdmin.String()): LevelAdmin | LevelWrite | LevelRead,
}

// validatePermissions validates that the requested permissions are within
// what should be allowed based on the configuration for the repository.
func validatePermissions(allowed, requested map[string]string) error {
	for name, reqLevel := range requested {
		allowLevel, ok := allowed[name]
		if !ok {
			return fmt.Errorf("requested permission %q is not authorized", name)
		}
		// if the requested level is not part of the allowed level reject it
		if levelInheritence[strings.ToLower(allowLevel)]&levels[strings.ToLower(reqLevel)] == 0 {
			return fmt.Errorf("requested permission level %q for permission %q is not authorized", reqLevel, name)
		}
	}
	return nil
}
