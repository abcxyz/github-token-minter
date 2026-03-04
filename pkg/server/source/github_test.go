// Copyright 2026 The Authors (see AUTHORS file)
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

package source

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

type mockTransport struct {
	responses []*http.Response
	errs      []error
	callCount int
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.callCount >= len(m.responses) && m.callCount >= len(m.errs) {
		return nil, errors.New("mock transport exhausted")
	}
	resp := m.responses[m.callCount]
	err := m.errs[m.callCount]
	m.callCount++
	return resp, err
}

func TestRetryRoundTripper_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		retryConfig *GitHubRetryConfig
		responses   []*http.Response
		errs        []error
		wantCalls   int
		wantErr     bool
		wantStatus  int
	}{
		{
			name: "success_no_retry",
			retryConfig: &GitHubRetryConfig{
				MaxRetries:     3,
				InitialBackoff: 1 * time.Millisecond,
				MaxBackoff:     10 * time.Millisecond,
				Multiplier:     1,
			},
			responses: []*http.Response{
				{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString("success"))},
			},
			errs:       []error{nil},
			wantCalls:  1,
			wantStatus: 200,
		},
		{
			name: "retry_500_success",
			retryConfig: &GitHubRetryConfig{
				MaxRetries:     3,
				InitialBackoff: 1 * time.Millisecond,
				MaxBackoff:     10 * time.Millisecond,
				Multiplier:     1,
			},
			responses: []*http.Response{
				{StatusCode: 500, Body: io.NopCloser(bytes.NewBufferString("error"))},
				{StatusCode: 502, Body: io.NopCloser(bytes.NewBufferString("error"))},
				{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString("success"))},
			},
			errs:       []error{nil, nil, nil},
			wantCalls:  3,
			wantStatus: 200,
		},
		{
			name: "retry_500_fail",
			retryConfig: &GitHubRetryConfig{
				MaxRetries:     2,
				InitialBackoff: 1 * time.Millisecond,
				MaxBackoff:     10 * time.Millisecond,
				Multiplier:     1,
			},
			responses: []*http.Response{
				{StatusCode: 500, Body: io.NopCloser(bytes.NewBufferString("error"))},
				{StatusCode: 500, Body: io.NopCloser(bytes.NewBufferString("error"))},
				{StatusCode: 500, Body: io.NopCloser(bytes.NewBufferString("error"))},
			},
			errs:      []error{nil, nil, nil},
			wantCalls: 3, // Initial + 2 retries
			wantErr:   true,
		},
		{
			name: "no_retry_404_by_default",
			retryConfig: &GitHubRetryConfig{
				MaxRetries:     3,
				InitialBackoff: 1 * time.Millisecond,
				MaxBackoff:     10 * time.Millisecond,
				Multiplier:     1,
			},
			responses: []*http.Response{
				{StatusCode: 404, Body: io.NopCloser(bytes.NewBufferString("not found"))},
			},
			errs:       []error{nil},
			wantCalls:  1,
			wantStatus: 404,
		},
		{
			name: "retry_404_configured",
			retryConfig: &GitHubRetryConfig{
				MaxRetries:     3,
				InitialBackoff: 1 * time.Millisecond,
				MaxBackoff:     10 * time.Millisecond,
				Multiplier:     1,
				Retry404:       true,
			},
			responses: []*http.Response{
				{StatusCode: 404, Body: io.NopCloser(bytes.NewBufferString("not found"))},
				{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString("success"))},
			},
			errs:       []error{nil, nil},
			wantCalls:  2,
			wantStatus: 200,
		},
		{
			name: "network_error_retry",
			retryConfig: &GitHubRetryConfig{
				MaxRetries:     3,
				InitialBackoff: 1 * time.Millisecond,
				MaxBackoff:     10 * time.Millisecond,
				Multiplier:     1,
			},
			responses: []*http.Response{
				nil,
				{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString("success"))},
			},
			errs:       []error{errors.New("conn reset"), nil},
			wantCalls:  2,
			wantStatus: 200,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mock := &mockTransport{
				responses: tc.responses,
				errs:      tc.errs,
			}

			rt := &RetryRoundTripper{
				Transport:   mock,
				RetryConfig: tc.retryConfig,
			}

			req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://example.com", nil)
			resp, err := rt.RoundTrip(req)
			if resp != nil && resp.Body != nil {
				defer resp.Body.Close()
			}

			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if resp.StatusCode != tc.wantStatus {
					t.Errorf("expected status %d, got %d", tc.wantStatus, resp.StatusCode)
				}
			}

			if mock.callCount != tc.wantCalls {
				t.Errorf("expected %d calls, got %d", tc.wantCalls, mock.callCount)
			}
		})
	}
}
