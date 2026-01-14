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
// that are decoupled from any specific command logic (sign, verify, inspect).
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

// BlobFetcher provides general-purpose blob fetching capabilities for OCI registries
// to support fetching arbitrary blobs (manifests, layers, configs, etc.).It
// provides low-level ORAS access without high-level abstractions.
type BlobFetcher struct {
	remoteRepo *remote.Repository
	reference  registry.Reference
}

// NewBlobFetcher creates a new BlobFetcher for the given reference.
// The remoteRepo parameter should be a pre-configured ORAS repository with proper
// authentication already applied.
// This decouples the fetcher from authentication logic.
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
