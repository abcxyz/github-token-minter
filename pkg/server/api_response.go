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

package server

// APIResponse is a structure that contains a http status code,
// a string response message and any error that might have occurred
// in the processing of an API request.
type APIResponse struct {
	HTTPCode    int
	HTTPMessage string
	Error       error
}

// NewAPIResponse creates a new APIResponse object with the specified
// values.
func NewAPIResponse(code int, msg string, err error) *APIResponse {
	return &APIResponse{code, msg, err}
}
