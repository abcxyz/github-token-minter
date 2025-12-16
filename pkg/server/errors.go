// Copyright 2023 The Authors (see AUTHORS file)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/abcxyz/pkg/logging"
)

// Standard error codes for the API.
const (
	ErrCodeInvalidRequest = "INVALID_REQUEST"
	ErrCodeInvalidBody    = "INVALID_BODY"
	ErrCodeMissingHeader  = "MISSING_HEADER"
	ErrCodeUnauthorized   = "UNAUTHORIZED"
	ErrCodeForbidden      = "FORBIDDEN"
	ErrCodeInternal       = "INTERNAL_ERROR"
)

// apiResponse is a structure that contains a http status code,
// a string response message and any error that might have occurred
// in the processing of a request.
type apiResponse struct {
	Code     int
	ErrCode  string
	Message  string
	Result   interface{}
	Internal error
}

// JSONErrorResponse defines the structure of the error response sent to clients.
type JSONErrorResponse struct {
	Ok      bool   `json:"ok"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// JSONSuccessResponse defines the structure of the success response sent to clients.
type JSONSuccessResponse struct {
	Ok     bool        `json:"ok"`
	Result interface{} `json:"result,omitempty"`
}

// writeAPIResponse handles monitoring and logging of errors and writing the JSON response.
func writeAPIResponse(ctx context.Context, w http.ResponseWriter, resp *apiResponse) {
	logger := logging.FromContext(ctx)

	if resp.Internal != nil {
		logger.ErrorContext(ctx, "error processing request",
			"code", resp.Code,
			"error", resp.Internal,
			"message", resp.Message,
		)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.Code)

	var body interface{}
	if resp.Code >= 400 {
		body = JSONErrorResponse{
			Ok:      false,
			Code:    resp.ErrCode,
			Message: resp.Message,
		}
	} else {
		body = JSONSuccessResponse{
			Ok:     true,
			Result: resp.Result,
		}
	}

	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.ErrorContext(ctx, "failed to write json response", "error", err)
		// Fallback to basic error if JSON fails, though highly unlikely
		http.Error(w, `{"ok":false,"code":"INTERNAL_ERROR","message":"failed to encode response"}`, http.StatusInternalServerError)
	}
}
