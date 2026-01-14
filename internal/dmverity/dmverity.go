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

// Package dmverity provides dm-verity signing functionality for OCI image layers
package dmverity

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation/v2/internal/envelope/pkcs7"
	"github.com/notaryproject/notation/v2/internal/erofs"
	"github.com/notaryproject/notation/v2/internal/registryutil"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// LayerSignature represents a dm-verity signature for a single layer
type LayerSignature struct {
	LayerDigest string // Original layer digest
	RootHash    string // dm-verity root hash
	Signature   []byte // PKCS#7 signature of the root hash
}

// SignatureManifest represents the dm-verity signature manifest structure
type SignatureManifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	ArtifactType  string               `json:"artifactType"`
	Config        ocispec.Descriptor   `json:"config"`
	Layers        []ocispec.Descriptor `json:"layers"`
	Subject       *ocispec.Descriptor  `json:"subject,omitempty"`
	Annotations   map[string]string    `json:"annotations,omitempty"`
}

// SignImageLayers signs all layers in an OCI image with dm-verity.
func SignImageLayers(ctx context.Context, primitiveSigner signature.Signer, fetcher *registryutil.BlobFetcher, manifest ocispec.Manifest) ([]LayerSignature, error) {
	var signatures []LayerSignature

	for _, layer := range manifest.Layers {
		// Download layer blob
		layerData, err := fetcher.FetchBlob(ctx, layer)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch layer blob %s from registry: %w", layer.Digest.String(), err)
		}

		// Generate dm-verity root hash for this layer
		rootHash, err := ComputeRootHash(layerData)
		if err != nil {
			return nil, fmt.Errorf("failed to generate dm-verity root hash for layer %s: %w", layer.Digest.String(), err)
		}

		// Sign the root hash using PKCS#7
		sig, err := signRootHashPKCS7(primitiveSigner, rootHash)
		if err != nil {
			return nil, fmt.Errorf("failed to sign root hash for layer %s: %w", layer.Digest.String(), err)
		}

		layerSig := LayerSignature{
			LayerDigest: layer.Digest.String(),
			RootHash:    rootHash,
			Signature:   sig,
		}
		signatures = append(signatures, layerSig)
	}

	return signatures, nil
}

// ComputeRootHash converts a compressed layer to EROFS and computes its dm-verity root hash.
func ComputeRootHash(layerData []byte) (string, error) {
	ctx := context.Background()

	// Step 1: Convert tar.gz layer to EROFS format using converter
	converter := erofs.NewConverter("")
	erofsData, err := converter.ConvertLayerToEROFS(ctx, layerData)
	if err != nil {
		return "", fmt.Errorf("EROFS conversion failed: %w", err)
	}

	// Step 2: Calculate dm-verity root hash using veritysetup
	// Parameters must match the runtime containerd snapshotter
	calculator := erofs.NewVerityCalculator("")
	opts := erofs.DefaultVeritysetupOptions()
	rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
	if err != nil {
		return "", fmt.Errorf("dm-verity root hash calculation failed: %w", err)
	}

	return rootHash, nil
}

// signRootHashPKCS7 signs a dm-verity root hash using PKCS#7 format.
func signRootHashPKCS7(primitiveSigner signature.Signer, rootHash string) ([]byte, error) {
	// Create PKCS#7 signer from the primitive signer
	pkcs7Signer, err := pkcs7.NewSigner(primitiveSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#7 signer (check that signing key supports RSASSA-PKCS1-v1_5): %w", err)
	}

	// Sign the hex string of the root hash (not the decoded raw bytes)
	// This matches the OpenSSL smime behavior which signs the literal input
	sig, err := pkcs7Signer.Sign([]byte(rootHash))
	if err != nil {
		return nil, fmt.Errorf("PKCS#7 signing failed: %w", err)
	}

	if len(sig) == 0 {
		return nil, fmt.Errorf("PKCS#7 signer produced empty signature for root hash %s", rootHash)
	}

	return sig, nil
}

// CreateSignatureManifest creates an OCI manifest for dm-verity signatures.
func CreateSignatureManifest(signatures []LayerSignature, subjectManifest ocispec.Descriptor) (*SignatureManifest, error) {
	sigManifest := &SignatureManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		ArtifactType:  "application/vnd.oci.mt.pkcs7", // Containerd-compatible artifact type
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			// OCI standard empty config digest: sha256 of "{}" (2 bytes)
			Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
			Size:   2,
		},
		Subject: &subjectManifest,
		Annotations: map[string]string{
			"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
		},
	}

	// Create a layer descriptor for each signature in containerd-compatible format
	for _, sig := range signatures {
		// Calculate actual digest of the signature blob
		sigDigest := digest.FromBytes(sig.Signature)

		// Base64 encode the PKCS#7 signature for the annotation (containerd format)
		sigBase64 := base64.StdEncoding.EncodeToString(sig.Signature)

		layerDesc := ocispec.Descriptor{
			MediaType: "application/vnd.oci.image.layer.v1.erofs.sig", // Containerd-compatible media type
			Digest:    sigDigest,
			Size:      int64(len(sig.Signature)),
			Annotations: map[string]string{
				"image.layer.digest":    sig.LayerDigest,
				"image.layer.root_hash": sig.RootHash,
				"image.layer.signature": sigBase64,
				"signature.blob.name":   fmt.Sprintf("signature_for_layer_%s.json", sig.LayerDigest[7:]), // Remove "sha256:" prefix
			},
		}
		sigManifest.Layers = append(sigManifest.Layers, layerDesc)
	}

	return sigManifest, nil
}
