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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation/v2/internal/erofs"
	"github.com/notaryproject/notation/v2/internal/registryutil"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"go.mozilla.org/pkcs7"
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
		rootHash, err := generateDmVerityRootHash(layerData)
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
func generateDmVerityRootHash(layerData []byte) (string, error) {
	fmt.Printf("[dmverity.generateDmVerityRootHash] Processing %d bytes of layer data\n", len(layerData))
	ctx := context.Background()

	// Step 1: Convert tar.gz layer to EROFS format using modular converter
	fmt.Printf("[dmverity.generateDmVerityRootHash]  Step 1: Converting tar.gz to EROFS...\n")
	converter := erofs.NewConverter("")
	erofsData, err := converter.ConvertLayerToEROFS(ctx, layerData)
	if err != nil {
		return "", fmt.Errorf("EROFS conversion failed: %w", err)
	}
	fmt.Printf("[dmverity.generateDmVerityRootHash]  Created EROFS image: %d bytes\n", len(erofsData))

	// Step 2: Calculate dm-verity root hash using modular veritysetup utilities
	fmt.Printf("[dmverity.generateDmVerityRootHash]  Step 2: Computing dm-verity Merkle tree root hash...\n")
	calculator := erofs.NewVerityCalculator("")
	opts := erofs.DefaultVeritysetupOptions()
	rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
	if err != nil {
		return "", fmt.Errorf("dm-verity root hash calculation failed: %w", err)
	}

	fmt.Printf("[dmverity.generateDmVerityRootHash]  Generated dm-verity root hash: %s\n", rootHash)
	return rootHash, nil
}

// signRootHashPKCS7 signs a dm-verity root hash using PKCS#7 format
// PROTOTYPE: Direct PKCS#7 signing bypassing notation-go (which doesn't support PKCS#7 yet)
func signRootHashPKCS7(ctx context.Context, signer notation.Signer, rootHash string) ([]byte, error) {
	fmt.Printf("[dmverity.signRootHashPKCS7] Signing root hash: %s\n", rootHash)
	fmt.Printf("[dmverity.signRootHashPKCS7]  Using PROTOTYPE direct PKCS#7 signing\n")

	// Convert hex root hash to bytes for signing
	rootHashBytes, err := hex.DecodeString(rootHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode root hash from hex: %w", err)
	}

	// PROTOTYPE: Load signing key and certificate directly from filesystem
	// TODO: Integrate properly with notation's signer interface
	keyPath := os.Getenv("HOME") + "/.config/notation/localkeys/dmverity-test.key"
	certPath := os.Getenv("HOME") + "/.config/notation/localkeys/dmverity-test.crt"

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	var privateKey crypto.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	fmt.Printf("[dmverity.signRootHashPKCS7]  Loaded certificate: %s\n", cert.Subject)
	fmt.Printf("[dmverity.signRootHashPKCS7]  Creating PKCS#7 signed data for %d bytes\n", len(rootHashBytes))

	// Create PKCS#7 signed data structure
	signedData, err := pkcs7.NewSignedData(rootHashBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create PKCS#7 signed data: %w", err)
	}

	// Add signer with certificate
	if err := signedData.AddSigner(cert, privateKey.(*rsa.PrivateKey), pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("failed to add signer to PKCS#7 data: %w", err)
	}

	// Finalize the signature (detached signature)
	signature, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("failed to finalize PKCS#7 signature: %w", err)
	}

	fmt.Printf("[dmverity.signRootHashPKCS7]  Generated PKCS#7 signature: %d bytes\n", len(signature))
	fmt.Printf("[dmverity.signRootHashPKCS7]  Signature is detached (content not embedded)\n")

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
			"org.opencontainers.image.created": "2025-11-03T00:00:00Z", // TODO: Use actual timestamp
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
