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
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abcxyz/pkg/githubauth"
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
			name: "no_retry_422_by_default",
			retryConfig: &GitHubRetryConfig{
				MaxRetries:     3,
				InitialBackoff: 1 * time.Millisecond,
				MaxBackoff:     10 * time.Millisecond,
				Multiplier:     1,
			},
			responses: []*http.Response{
				{StatusCode: 422, Body: io.NopCloser(bytes.NewBufferString("unprocessable"))},
			},
			errs:       []error{nil},
			wantCalls:  1,
			wantStatus: 422,
		},
		{
			name: "retry_422",
			retryConfig: &GitHubRetryConfig{
				MaxRetries:     3,
				InitialBackoff: 1 * time.Millisecond,
				MaxBackoff:     10 * time.Millisecond,
				Multiplier:     1,
				Retry422:       true,
			},
			responses: []*http.Response{
				{StatusCode: 422, Body: io.NopCloser(bytes.NewBufferString("unprocessable"))},
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

func TestGitHubSourceSystem_RetrieveFileContents_PanicFix(t *testing.T) {
	t.Parallel()

	mock := &urlMockTransport{t: t}
	httpClient := &http.Client{Transport: mock}

	// Create a dummy app
	signer := &mockSigner{}
	app, err := githubauth.NewApp("123", signer, githubauth.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	g := &gitHubSourceSystem{
		apps:       []*githubauth.App{app},
		httpClient: httpClient,
	}

	ctx := t.Context()
	_, err = g.RetrieveFileContents(ctx, "my-org", "my-repo", "my-file", "main")

	// We expect an error because the mock returns an error for the file content call.
	if err == nil {
		t.Error("expected error, got nil")
	}
}

type urlMockTransport struct {
	t *testing.T
}

func (m *urlMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.t.Logf("Mock called for URL: %s", req.URL.Path)
	if strings.Contains(req.URL.Path, "/orgs/my-org/installation") {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewBufferString(`{"id": 123}`)),
		}, nil
	}
	if strings.Contains(req.URL.Path, "/app/installations/123/access_tokens") {
		return &http.Response{
			StatusCode: 201,
			Body:       io.NopCloser(bytes.NewBufferString(`{"token": "fake-token"}`)),
		}, nil
	}
	if strings.Contains(req.URL.Path, "/repos/my-org/my-repo/contents/my-file") {
		// Return error and nil response to trigger the panic!
		return nil, errors.New("network error")
	}
	return nil, fmt.Errorf("unexpected URL: %s", req.URL.String())
}

type mockSigner struct{}

func (m *mockSigner) Public() crypto.PublicKey { return nil }
func (m *mockSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return []byte("fake-sig"), nil
}
