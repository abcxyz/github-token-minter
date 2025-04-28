// Copyright 2025 The Authors (see AUTHORS file)
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

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/abcxyz/github-token-minter/pkg/server/source"
	"github.com/abcxyz/pkg/githubauth"
	"github.com/abcxyz/pkg/logging"
	"github.com/abcxyz/pkg/testutil"
)

func exportPrivateKeyAsPemStr(privkey *rsa.PrivateKey) (string, error) {
	privkeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return string(privkeyPem), nil
}

func TestCreateAppConfigs(t *testing.T) {
	t.Parallel()

	ctx := logging.WithLogger(t.Context(), logging.TestLogger(t))
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey, err := exportPrivateKeyAsPemStr(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	pkSigner, err := githubauth.NewPrivateKeySigner(pemKey)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name               string
		sourcesSystemAuths []string
		want               []*source.GitHubAppConfig
		expErr             bool
		expErrMsg          string
	}{
		{
			name:               "missing configurations",
			sourcesSystemAuths: []string{},
			want:               []*source.GitHubAppConfig{},
			expErr:             true,
			expErrMsg:          "",
		},
		{
			name:               "single configurations - private key",
			sourcesSystemAuths: []string{fmt.Sprintf(`gha://1234?private_key=%s`, pemKey)},
			want: []*source.GitHubAppConfig{
				{
					AppID:  "1234",
					Signer: pkSigner,
				},
			},
			expErr:    false,
			expErrMsg: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &Config{SourceSystemAuth: tc.sourcesSystemAuths}

			got, err := createAppConfigs(ctx, cfg)
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreFields(source.GitHubAppConfig{}, "Signer")); diff != "" {
				t.Errorf("mismatch (-want, +got):\n%s", diff)
			}

			if msg := testutil.DiffErrString(err, tc.expErrMsg); msg != "" {
				t.Fatal(msg)
			}
			if !tc.expErr && got == nil && tc.want != nil {
				t.Errorf("result nil without error")
			}
		})
	}
}
