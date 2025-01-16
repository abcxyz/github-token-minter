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

package privatekey

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// KeyServer provides functionalities regarding KMS private key import.
type KeyServer struct {
	kms *kms.KeyManagementClient
}

func NewKeyServer(ctx context.Context, kms *kms.KeyManagementClient) (*KeyServer, error) {
	return &KeyServer{kms}, nil
}

// GetOrCreateKeyRing get the existing key ring or create a key ring if it doesn't exist.
func (s *KeyServer) GetOrCreateKeyRing(ctx context.Context, projectID, location, keyRing string) (*kmspb.KeyRing, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s", projectID, location)

	// Check if the key ring already exists.
	getKeyRingReq := &kmspb.GetKeyRingRequest{
		Name: fmt.Sprintf("%s/keyRings/%s", parent, keyRing),
	}
	fetchedKeyRing, err := s.kms.GetKeyRing(ctx, getKeyRingReq)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// Key ring doesn't exist, create it.
			req := &kmspb.CreateKeyRingRequest{
				Parent:    parent,
				KeyRingId: keyRing,
			}
			createdKeyRing, err := s.kms.CreateKeyRing(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("failed to create key ring with parent %q and id %q: %w", parent, keyRing, err)
			}
			return createdKeyRing, nil
		}
		return nil, fmt.Errorf("failed to query key ring with parent %q and id %q: %w", parent, keyRing, err)
	}

	// Key ring already exists.
	return fetchedKeyRing, nil
}

// GetOrCreateKey get the existing key or create a key if it doesn't exist.
func (s *KeyServer) GetOrCreateKey(ctx context.Context, projectID, location, keyRing, key string) (*kmspb.CryptoKey, error) {
	keyPath := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s", projectID, location, keyRing, key)

	fetchedKey, err := s.kms.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: keyPath,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// Key doesn't exist, create it.
			req := &kmspb.CreateCryptoKeyRequest{
				Parent:      fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, location, keyRing),
				CryptoKeyId: key,
				CryptoKey: &kmspb.CryptoKey{
					Purpose:    kmspb.CryptoKey_ASYMMETRIC_SIGN,
					ImportOnly: true,
					VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
						Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
					},
				},
				SkipInitialVersionCreation: true,
			}

			createdKey, err := s.kms.CreateCryptoKey(ctx, req)
			if err != nil {
				return nil, fmt.Errorf("failed to create key with key path %q: %w", keyPath, err)
			}
			return createdKey, nil
		}
		return nil, fmt.Errorf("failed to query key ring with key path %q: %w", keyPath, err)
	}

	return fetchedKey, nil
}
