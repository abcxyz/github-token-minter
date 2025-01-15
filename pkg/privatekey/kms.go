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

// CreateKeyRingIfNotExists create a key ring if it doesn't exist
func (s *KeyServer) CreateKeyRingIfNotExists(ctx context.Context, projectID, location, keyRing string) (*kmspb.KeyRing, error) {
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
