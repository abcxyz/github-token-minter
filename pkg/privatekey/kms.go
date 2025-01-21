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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/google/tink/go/kwp/subtle"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyz"
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

// GetOrCreateImportJob get the existing active import job or create an import job if it doesn't exist.
func (s *KeyServer) GetOrCreateImportJob(ctx context.Context, projectID, location, keyRing, importJobPrefix string) (*kmspb.ImportJob, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", projectID, location, keyRing)

	// be careful when you change the import method, it may cause import failure
	listReq := &kmspb.ListImportJobsRequest{
		Parent:   parent,
		Filter:   "state = ACTIVE AND protectionLevel = SOFTWARE AND importMethod = RSA_OAEP_4096_SHA256_AES_256",
		PageSize: 1000,
	}
	it := s.kms.ListImportJobs(ctx, listReq)

	var jobs []*kmspb.ImportJob
	for {
		job, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list import jobs with parent %q: %w", parent, err)
		}
		slices := strings.Split(job.GetName(), "/")
		jobName := slices[len(slices)-1]
		if strings.HasPrefix(jobName, importJobPrefix) {
			jobs = append(jobs, job)
		}
	}
	if len(jobs) > 0 {
		return jobs[0], nil
	}

	jobID, err := generateImportJobID(importJobPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to genereate import job id: %w", err)
	}

	// be careful when you change the import method, it may cause import failure
	createReq := &kmspb.CreateImportJobRequest{
		Parent:      parent,
		ImportJobId: jobID,
		ImportJob: &kmspb.ImportJob{
			ImportMethod:    kmspb.ImportJob_RSA_OAEP_4096_SHA256_AES_256,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
	}
	newJob, err := s.kms.CreateImportJob(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create import job: %w", err)
	}
	return newJob, nil
}

// GetImportJob get an ImportJob in KMS.
func (s *KeyServer) GetImportJob(ctx context.Context, name string) (*kmspb.ImportJob, error) {
	job, err := s.kms.GetImportJob(ctx, &kmspb.GetImportJobRequest{
		Name: name,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get import job %q: %w", name, err)
	}
	return job, nil
}

func (s *KeyServer) ImportManuallyWrappedKey(ctx context.Context, importJobName, cryptoKeyName, key string) (*kmspb.CryptoKeyVersion, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the key: %w", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to format private key: %w", err)
	}

	// Generate a temporary 32-byte key for AES-KWP and wrap the key material.
	kwpKey := make([]byte, 32)
	if _, err := rand.Read(kwpKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES-KWP key: %w", err)
	}
	kwp, err := subtle.NewKWP(kwpKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create KWP cipher: %w", err)
	}
	wrappedTarget, err := kwp.Wrap(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap target key with KWP: %w", err)
	}

	// Retrieve the public key from the import job.
	importJob, err := s.kms.GetImportJob(ctx, &kmspb.GetImportJobRequest{
		Name: importJobName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve import job: %w", err)
	}
	pubBlock, _ := pem.Decode([]byte(importJob.PublicKey.Pem))
	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse import job public key: %w", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected public key type %T, want *rsa.PublicKey", pubAny)
	}

	// Wrap the KWP key using the import job key.
	wrappedWrappingKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, kwpKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap KWP key: %w", err)
	}

	// Concatenate the wrapped KWP key and the wrapped target key.
	combined := append(wrappedWrappingKey, wrappedTarget...)

	// Build the request.
	req := &kmspb.ImportCryptoKeyVersionRequest{
		Parent:     cryptoKeyName,
		ImportJob:  importJobName,
		Algorithm:  kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		WrappedKey: combined,
	}

	// Call the API.
	keyVersion, err := s.kms.ImportCryptoKeyVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to import crypto key version: %w", err)
	}
	return keyVersion, nil
}

// GetKeyVersion gets a existing key version in KMS.
func (s *KeyServer) GetKeyVersion(ctx context.Context, name string) (*kmspb.CryptoKeyVersion, error) {
	keyVersion, err := s.kms.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: name,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get import job %q: %w", name, err)
	}
	return keyVersion, nil
}

func generateImportJobID(prefix string) (string, error) {
	randomS, err := randomString(4)
	if err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	return fmt.Sprintf("%s-%s", prefix, randomS), nil
}

func randomString(n int) (string, error) {
	r := make([]byte, n)
	for i := range r {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}
		r[i] = letterBytes[randomIndex.Int64()]
	}
	return string(r), nil
}
