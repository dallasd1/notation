// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package registryutil provides general-purpose utilities for OCI registry operations
// that extend beyond the signature-specific functionality in notation-go/registry.
// These utilities are decoupled from any specific command logic (sign, verify, inspect)
// and can be reused across the codebase for any blob fetching needs.
package registryutil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

// BlobFetcher provides general-purpose blob fetching capabilities for OCI registries.
// This extends the signature-specific notation-go/registry.Repository interface
// to support fetching arbitrary blobs (manifests, layers, configs, etc.).
//
// Design Philosophy:
// - Decoupled from specific command logic (dm-verity, inspect, etc.)
// - Reusable across any part of the codebase that needs blob access
// - Provides low-level ORAS access without high-level notation abstractions
type BlobFetcher struct {
	remoteRepo *remote.Repository
	reference  registry.Reference
}

// NewBlobFetcher creates a new BlobFetcher for the given reference.
// This provides low-level ORAS access for fetching any blob type.
//
// The remoteRepo parameter should be a pre-configured ORAS repository with proper
// authentication, TLS settings, and other security options already applied.
// This design allows the fetcher to remain decoupled from authentication logic.
func NewBlobFetcher(ctx context.Context, reference string, remoteRepo *remote.Repository) (*BlobFetcher, error) {
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference %s: %w", reference, err)
	}

	return &BlobFetcher{
		remoteRepo: remoteRepo,
		reference:  ref,
	}, nil
}

// FetchManifest fetches and parses an OCI manifest from the registry.
// Returns the parsed manifest structure with all layer information.
//
// This is a general-purpose manifest fetcher that works for any manifest type.
// It can be used for dm-verity signing, inspection, verification, or any other
// operation that needs access to manifest layer information.
func (f *BlobFetcher) FetchManifest(ctx context.Context, manifestDesc ocispec.Descriptor) (*ocispec.Manifest, error) {
	reader, err := f.remoteRepo.Fetch(ctx, manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest blob: %w", err)
	}
	defer reader.Close()

	manifestBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest content: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest JSON: %w", err)
	}

	return &manifest, nil
}

// FetchBlob fetches any blob by descriptor and returns the raw content.
// This is a general-purpose blob fetcher for layers, configs, or other artifacts.
//
// Use this when you need the complete blob content in memory.
// For large blobs, consider using FetchBlobStream instead.
func (f *BlobFetcher) FetchBlob(ctx context.Context, desc ocispec.Descriptor) ([]byte, error) {
	reader, err := f.remoteRepo.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch blob %s: %w", desc.Digest, err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob content: %w", err)
	}

	return content, nil
}

// FetchBlobStream fetches a blob and returns a stream reader.
// Useful for large blobs where you want to process content incrementally
// without loading the entire blob into memory.
//
// The caller is responsible for closing the returned io.ReadCloser.
func (f *BlobFetcher) FetchBlobStream(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	reader, err := f.remoteRepo.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch blob stream %s: %w", desc.Digest, err)
	}
	return reader, nil
}

// GetReference returns the parsed registry reference.
// Useful for logging or identifying which registry/repository is being accessed.
func (f *BlobFetcher) GetReference() registry.Reference {
	return f.reference
}

// GetRepository returns the underlying ORAS repository for advanced operations.
// Use this if you need direct access to ORAS functionality not exposed by BlobFetcher.
func (f *BlobFetcher) GetRepository() *remote.Repository {
	return f.remoteRepo
}
