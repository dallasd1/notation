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
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/notaryproject/notation-go"
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
// Uses the decoupled registryutil.BlobFetcher for fetching layer blobs.
func SignImageLayers(ctx context.Context, signer notation.Signer, fetcher *registryutil.BlobFetcher, manifest ocispec.Manifest) ([]LayerSignature, error) {
	fmt.Printf("[dmverity.SignImageLayers] Starting layer signing process for %d layers\n", len(manifest.Layers))
	var signatures []LayerSignature

	for i, layer := range manifest.Layers {
		fmt.Printf("*** [dmverity.SignImageLayers] Processing layer %d/%d: %s (size: %d bytes, mediaType: %s) ***\n",
			i+1, len(manifest.Layers), layer.Digest.String(), layer.Size, layer.MediaType)

		// Download layer blob using the decoupled fetcher
		fmt.Printf("[dmverity.SignImageLayers]  Fetching layer blob data for %s\n", layer.Digest.String())

		layerData, err := fetcher.FetchBlob(ctx, layer)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch layer blob: %w", err)
		}
		fmt.Printf("[dmverity.SignImageLayers]  Retrieved %d bytes of layer data\n", len(layerData))

		// Generate dm-verity root hash for this layer
		fmt.Printf("[dmverity.SignImageLayers]  Generating dm-verity root hash for layer %s\n", layer.Digest.String())
		rootHash, err := ComputeRootHash(layerData, layer.Digest.String())
		if err != nil {
			return nil, fmt.Errorf("failed to generate dm-verity root hash for layer %s: %w", layer.Digest.String(), err)
		}
		fmt.Printf("[dmverity.SignImageLayers]  Generated root hash: %s\n", rootHash)

		// Sign the root hash using PKCS#7
		fmt.Printf("[dmverity.SignImageLayers]  Signing root hash with PKCS#7 format\n")
		signature, err := signRootHashPKCS7(ctx, signer, rootHash)
		if err != nil {
			return nil, fmt.Errorf("failed to sign root hash for layer %s: %w", layer.Digest.String(), err)
		}
		fmt.Printf("[dmverity.SignImageLayers]  Generated PKCS#7 signature: %d bytes\n", len(signature))

		layerSig := LayerSignature{
			LayerDigest: layer.Digest.String(),
			RootHash:    rootHash,
			Signature:   signature,
		}
		signatures = append(signatures, layerSig)
		fmt.Printf("[dmverity.SignImageLayers]  Completed layer %d: digest=%s, rootHash=%s, sigBytes=%d\n",
			i+1, layerSig.LayerDigest, layerSig.RootHash, len(layerSig.Signature))
	}

	fmt.Printf("[dmverity.SignImageLayers] Successfully signed all %d layers\n", len(signatures))
	return signatures, nil
}

// generateDmVerityRootHash generates the dm-verity root hash for a layer.
// Uses modular utilities from internal/erofs package:
// 1. EROFS Converter: tar.gz -> EROFS filesystem
// 2. Veritysetup Calculator: EROFS -> dm-verity root hash
//
// This follows the pattern established by registryutil.BlobFetcher for modularity.
// ComputeRootHash converts a compressed layer to EROFS and computes
// its dm-verity root hash using kata-compatible parameters.
func ComputeRootHash(layerData []byte, layerDigest string) (string, error) {
	fmt.Printf("[dmverity.generateDmVerityRootHash] Processing %d bytes of layer data\n", len(layerData))
	ctx := context.Background()

	// Step 1: Convert tar.gz layer to EROFS format using modular converter
	fmt.Printf("[dmverity.generateDmVerityRootHash]  Step 1: Converting tar.gz to EROFS...\n")
	converter := erofs.NewConverter("")
	erofsData, err := converter.ConvertLayerToEROFS(ctx, layerData, layerDigest)
	if err != nil {
		return "", fmt.Errorf("EROFS conversion failed: %w", err)
	}
	fmt.Printf("[dmverity.generateDmVerityRootHash]  Created EROFS image: %d bytes\n", len(erofsData))

	// Step 2: Calculate dm-verity root hash using veritysetup
	fmt.Printf("[dmverity.generateDmVerityRootHash]  Step 2: Computing dm-verity Merkle tree root hash...\n")

	// DEBUG: Save EROFS image for inspection
	debugPath := "/tmp/notation_erofs_debug.img"
	if debugErr := os.WriteFile(debugPath, erofsData, 0644); debugErr == nil {
		fmt.Printf("[dmverity.ComputeRootHash] DEBUG: Saved EROFS image to %s (%d bytes)\n", debugPath, len(erofsData))
	}

	// Use veritysetup with kata-compatible parameters:
	// - 512-byte data and hash blocks (matches VERITY_BLOCK_SIZE)
	// - Zero salt for deterministic builds
	// - SHA256 algorithm
	calculator := erofs.NewVerityCalculator("")
	opts := erofs.DefaultVeritysetupOptions()
	rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
	if err != nil {
		return "", fmt.Errorf("dm-verity root hash calculation failed: %w", err)
	}

	fmt.Printf("[dmverity.generateDmVerityRootHash]  Generated dm-verity root hash: %s\n", rootHash)
	return rootHash, nil
}

// signRootHashPKCS7 signs a dm-verity root hash using PKCS#7 format via OpenSSL
// Uses OpenSSL for containerd compatibility
func signRootHashPKCS7(ctx context.Context, signer notation.Signer, rootHash string) ([]byte, error) {
	fmt.Printf("[dmverity.signRootHashPKCS7] Signing root hash: %s\n", rootHash)
	fmt.Printf("[dmverity.signRootHashPKCS7] Using OpenSSL smime -sign for PKCS#7\n")

	// Check if OpenSSL is available
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		return nil, fmt.Errorf("openssl not found in PATH (required for PKCS#7 signing): %w", err)
	}
	fmt.Printf("[dmverity.signRootHashPKCS7] Found OpenSSL: %s\n", opensslPath)

	// TODO: Integrate with notation's signer interface for dynamic key/cert loading
	keyPath := "/root/source/notation/dbsigner.key"
	certPath := "/root/source/notation/signerca.pem"

	// Verify files exist
	if _, err := os.Stat(keyPath); err != nil {
		return nil, fmt.Errorf("private key not found at %s: %w", keyPath, err)
	}
	if _, err := os.Stat(certPath); err != nil {
		return nil, fmt.Errorf("certificate not found at %s: %w", certPath, err)
	}

	// Build OpenSSL command for PKCS#7 signing:
	// openssl smime -sign -noattr -binary -inkey <key> -signer <cert> -outform der
	//
	// Flags:
	// -sign: Create PKCS#7 signature
	// -noattr: No signed attributes (required for containerd compatibility)
	// -binary: Binary input mode
	// -inkey: Private key file
	// -signer: Certificate file
	// -outform der: Output in DER format
	//
	// Input: hex string of root hash (e.g., "a181ece8b70d621f23cddb2d17624048...")
	// Output: DER-encoded PKCS#7 signature
	cmd := exec.CommandContext(ctx, "openssl", "smime",
		"-sign",
		"-noattr", // No signed attributes - required for containerd
		"-binary",
		"-inkey", keyPath,
		"-signer", certPath,
		"-outform", "der",
	)

	// Sign the hex string of the root hash (not the decoded raw bytes)
	cmd.Stdin = strings.NewReader(rootHash)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Printf("[dmverity.signRootHashPKCS7] Running: openssl smime -sign -noattr -binary -inkey %s -signer %s -outform der\n",
		keyPath, certPath)
	fmt.Printf("[dmverity.signRootHashPKCS7] Signing hex string (%d chars): %s\n", len(rootHash), rootHash)

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl smime failed: %w, stderr: %s", err, stderr.String())
	}

	signature := stdout.Bytes()
	if len(signature) == 0 {
		return nil, fmt.Errorf("openssl produced empty signature, stderr: %s", stderr.String())
	}

	fmt.Printf("[dmverity.signRootHashPKCS7] Generated PKCS#7 signature: %d bytes (DER format)\n", len(signature))

	return signature, nil
}

// CreateSignatureManifest creates an OCI manifest for dm-verity signatures
func CreateSignatureManifest(signatures []LayerSignature, subjectManifest ocispec.Descriptor) (*SignatureManifest, error) {
	fmt.Printf("[dmverity.CreateSignatureManifest] Creating signature manifest for %d layer signatures\n", len(signatures))
	fmt.Printf("[dmverity.CreateSignatureManifest]  Subject manifest: %s (%s, %d bytes)\n",
		subjectManifest.Digest, subjectManifest.MediaType, subjectManifest.Size)

	// Use the exact format containerd expects for dm-verity signatures
	sigManifest := &SignatureManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		ArtifactType:  "application/vnd.oci.mt.pkcs7", // Containerd-compatible artifact type
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
			Size:      2,
		},
		Subject: &subjectManifest,
		Annotations: map[string]string{
			"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
		},
	}

	fmt.Printf("[dmverity.CreateSignatureManifest]  Created manifest structure with artifact type: %s\n", sigManifest.ArtifactType)

	// Create a layer descriptor for each signature in containerd-compatible format
	fmt.Printf("[dmverity.CreateSignatureManifest]  Building layer descriptors for signatures\n")
	for i, sig := range signatures {
		fmt.Printf("[dmverity.CreateSignatureManifest]  Processing signature %d: layer=%s, rootHash=%s, sigSize=%d\n",
			i+1, sig.LayerDigest, sig.RootHash, len(sig.Signature))

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
		fmt.Printf("[dmverity.CreateSignatureManifest]  Added layer descriptor: %s (%d bytes)\n",
			layerDesc.Digest, layerDesc.Size)
	}

	fmt.Printf("[dmverity.CreateSignatureManifest] Successfully created signature manifest with %d layers\n", len(sigManifest.Layers))
	return sigManifest, nil
}
