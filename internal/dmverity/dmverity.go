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
	"maps"
	"time"

	"github.com/google/uuid"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/pkcs7"
	"github.com/notaryproject/notation/v2/internal/erofs"
	"github.com/notaryproject/notation/v2/internal/registryutil"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// OCI media types and annotation keys used by dm-verity layer signatures.
const (
	ReferrerArtifactType    = "application/vnd.cncf.notary.dmverity.v1"
	LayerSignatureMediaType = "application/vnd.cncf.notary.dmverity.layer-signature+pkcs7"
	EROFSLayerMediaType     = "application/vnd.cncf.containerd.erofs.layer.v1"
	MerkleTreeMediaType     = "application/vnd.cncf.dmverity.merkle-tree.v1"

	AnnotationLayerDigest    = "io.cncf.notary.dmverity.layer-digest"
	AnnotationLayerRootHash  = "io.cncf.notary.dmverity.layer-roothash"
	AnnotationLayerSignature = "io.cncf.notary.dmverity.layer-signature"

	AnnotationSourceLayerDigest = "io.cncf.notary.dmverity.source-layer-digest"
	AnnotationRootHash          = "io.cncf.notary.dmverity.root-hash"
	AnnotationLayout            = "io.cncf.notary.dmverity.layout"

	SeparateHashDeviceLayout = "separate-hash-device-superblock-v1"
)

// SignatureEnvelope holds a dm-verity PKCS#7 signature envelope for a single layer.
type SignatureEnvelope struct {
	LayerDigest string
	RootHash    string
	Signature   []byte
	EROFSData   []byte
	MerkleTree  []byte
}

// SignatureManifest is the OCI referrer artifact containing dm-verity layer signatures.
type SignatureManifest struct {
	SchemaVersion int                  `json:"schemaVersion"`
	MediaType     string               `json:"mediaType"`
	ArtifactType  string               `json:"artifactType"`
	Config        ocispec.Descriptor   `json:"config"`
	Layers        []ocispec.Descriptor `json:"layers"`
	Subject       *ocispec.Descriptor  `json:"subject,omitempty"`
	Annotations   map[string]string    `json:"annotations,omitempty"`
}

// SignImageLayers signs all layer root hashes from OCI blob, generates PKCS#7 envelope, returns array of envelopes
func SignImageLayers(ctx context.Context, primitiveSigner signature.Signer, fetcher *registryutil.BlobFetcher, manifest ocispec.Manifest) ([]SignatureEnvelope, error) {
	var signatures []SignatureEnvelope

	for _, layer := range manifest.Layers {
		layerData, err := fetcher.FetchBlob(ctx, layer)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch layer blob %s from registry: %w", layer.Digest.String(), err)
		}

		layerArtifact, err := ComputeLayerArtifact(layer.Digest.String(), layerData)
		if err != nil {
			return nil, fmt.Errorf("failed to generate dm-verity root hash for layer %s: %w", layer.Digest.String(), err)
		}

		sig, err := signRootHashPKCS7(primitiveSigner, layerArtifact.RootHash)
		if err != nil {
			return nil, fmt.Errorf("failed to sign root hash for layer %s: %w", layer.Digest.String(), err)
		}

		layerSig := SignatureEnvelope{
			LayerDigest: layer.Digest.String(),
			RootHash:    layerArtifact.RootHash,
			Signature:   sig,
			EROFSData:   layerArtifact.EROFSData,
			MerkleTree:  layerArtifact.MerkleTree,
		}
		signatures = append(signatures, layerSig)
	}

	return signatures, nil
}

// ComputeRootHash converts a compressed layer blob to an EROFS image and computes its root hash.
// layerDigest is the OCI manifest descriptor digest of the layer (e.g.
// "sha256:..."); it is required so the EROFS superblock UUID matches what
// containerd's erofs-snapshotter computes at apply time.
func ComputeRootHash(layerDigest string, layerData []byte) (string, error) {
	ctx := context.Background()
	converter := erofs.NewConverter("")
	erofsData, err := converter.ConvertLayerToEROFS(ctx, layerDigest, layerData)
	if err != nil {
		return "", fmt.Errorf("EROFS conversion failed: %w", err)
	}

	calculator := erofs.NewVerityCalculator("")
	opts := erofs.DefaultVeritysetupOptions()
	rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
	if err != nil {
		return "", fmt.Errorf("dm-verity root hash calculation failed: %w", err)
	}
	return rootHash, nil
}

// LayerArtifact contains the exact precomputed bytes associated with one OCI
// layer and the root hash authorized by its PKCS#7 signature.
type LayerArtifact struct {
	RootHash   string
	EROFSData  []byte
	MerkleTree []byte
}

// ComputeLayerArtifact converts a compressed layer to EROFS and computes a
// deterministic dm-verity hash device that can be published as an OCI blob.
func ComputeLayerArtifact(layerDigest string, layerData []byte) (*LayerArtifact, error) {
	ctx := context.Background()

	converter := erofs.NewConverter("")
	erofsData, err := converter.ConvertLayerToEROFS(ctx, layerDigest, layerData)
	if err != nil {
		return nil, fmt.Errorf("EROFS conversion failed: %w", err)
	}

	calculator := erofs.NewVerityCalculator("")
	opts := erofs.DefaultVeritysetupOptions()
	opts.UUID = uuid.NewSHA1(uuid.NameSpaceURL, []byte("dmverity:blobs/"+layerDigest)).String()
	verityArtifact, err := calculator.CalculateArtifact(ctx, erofsData, &opts)
	if err != nil {
		return nil, fmt.Errorf("dm-verity artifact calculation failed: %w", err)
	}

	return &LayerArtifact{
		RootHash:   verityArtifact.RootHash,
		EROFSData:  erofsData,
		MerkleTree: verityArtifact.HashTree,
	}, nil
}

// signRootHashPKCS7 creates a PKCS#7 signature envelope for the given root hash using the provided signer.
func signRootHashPKCS7(primitiveSigner signature.Signer, rootHash string) ([]byte, error) {
	env := pkcs7.NewEnvelope()

	req := &signature.SignRequest{
		Signer: primitiveSigner,
		Payload: signature.Payload{
			ContentType: pkcs7.MediaTypeEnvelope,
			Content:     []byte(rootHash),
		},
	}

	sig, err := env.Sign(req)
	if err != nil {
		return nil, fmt.Errorf("PKCS#7 signing failed: %w", err)
	}

	if len(sig) == 0 {
		return nil, fmt.Errorf("PKCS#7 signer produced empty signature for root hash %s", rootHash)
	}

	return sig, nil
}

// CreateSignatureManifest builds an OCI referrer manifest for dm-verity signatures.
func CreateSignatureManifest(signatures []SignatureEnvelope, subjectManifest ocispec.Descriptor) (*SignatureManifest, error) {
	sigManifest := &SignatureManifest{
		SchemaVersion: 2,
		MediaType:     ocispec.MediaTypeImageManifest,
		ArtifactType:  ReferrerArtifactType,
		Config:        ocispec.DescriptorEmptyJSON,
		Subject:       &subjectManifest,
		Annotations: map[string]string{
			"org.opencontainers.image.created": time.Now().UTC().Format(time.RFC3339),
		},
	}

	for _, sig := range signatures {
		sigDigest := digest.FromBytes(sig.Signature)
		sigBase64 := base64.StdEncoding.EncodeToString(sig.Signature)

		layerDesc := ocispec.Descriptor{
			MediaType: LayerSignatureMediaType,
			Digest:    sigDigest,
			Size:      int64(len(sig.Signature)),
			Annotations: map[string]string{
				AnnotationLayerDigest:    sig.LayerDigest,
				AnnotationLayerRootHash:  sig.RootHash,
				AnnotationLayerSignature: sigBase64,
			},
		}
		sigManifest.Layers = append(sigManifest.Layers, layerDesc)

		commonAnnotations := map[string]string{
			AnnotationSourceLayerDigest: sig.LayerDigest,
			AnnotationRootHash:          sig.RootHash,
			AnnotationLayout:            SeparateHashDeviceLayout,
		}
		erofsDesc := ocispec.Descriptor{
			MediaType:   EROFSLayerMediaType,
			Digest:      digest.FromBytes(sig.EROFSData),
			Size:        int64(len(sig.EROFSData)),
			Annotations: maps.Clone(commonAnnotations),
		}
		treeDesc := ocispec.Descriptor{
			MediaType:   MerkleTreeMediaType,
			Digest:      digest.FromBytes(sig.MerkleTree),
			Size:        int64(len(sig.MerkleTree)),
			Annotations: maps.Clone(commonAnnotations),
		}
		sigManifest.Layers = append(sigManifest.Layers, erofsDesc, treeDesc)
	}

	return sigManifest, nil
}
