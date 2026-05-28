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

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/notaryproject/notation/v2/internal/dmverity"
	"github.com/notaryproject/notation/v2/internal/registryutil"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

// runVerifyDmVerity verifies dm-verity PKCS#7 layer signatures attached as an
// OCI referrer. It does not verify the image manifest's notation signature;
// run `notation verify` (without --dm-verity) separately for that.
func runVerifyDmVerity(ctx context.Context, opts *verifyOpts) error {
	printer := opts.printer

	roots, err := dmverity.LoadCAPool(opts.caPath)
	if err != nil {
		return err
	}

	sigRepo, err := getRepository(ctx, inputTypeRegistry, opts.reference, &opts.SecureFlagOpts, false)
	if err != nil {
		return err
	}
	subjectDesc, resolvedRef, err := resolveReferenceWithWarning(ctx, inputTypeRegistry, opts.reference, sigRepo, "verify")
	if err != nil {
		return err
	}
	if !isImageManifest(subjectDesc.MediaType) {
		return fmt.Errorf("dm-verity verify requires an image manifest, but %s resolves to %s; pass a digest that names a specific platform manifest", opts.reference, subjectDesc.MediaType)
	}

	ref, err := registry.ParseReference(opts.reference)
	if err != nil {
		return fmt.Errorf("failed to parse reference: %w", err)
	}
	remoteRepo, err := getRepositoryClient(ctx, &opts.SecureFlagOpts, ref)
	if err != nil {
		return fmt.Errorf("failed to get repository client: %w", err)
	}
	fetcher, err := registryutil.NewBlobFetcher(ctx, opts.reference, remoteRepo)
	if err != nil {
		return err
	}

	sigManifestDesc, err := findDmverityReferrer(ctx, remoteRepo, subjectDesc)
	if err != nil {
		return err
	}
	sigManifest, err := fetcher.FetchManifest(ctx, sigManifestDesc)
	if err != nil {
		return fmt.Errorf("failed to fetch dm-verity signature manifest %s: %w", sigManifestDesc.Digest, err)
	}
	if sigManifest.Subject == nil || sigManifest.Subject.Digest != subjectDesc.Digest {
		return fmt.Errorf("dm-verity signature manifest %s has subject %v, want %s", sigManifestDesc.Digest, sigManifest.Subject, subjectDesc.Digest)
	}
	imageManifest, err := fetcher.FetchManifest(ctx, subjectDesc)
	if err != nil {
		return fmt.Errorf("failed to fetch image manifest %s: %w", subjectDesc.Digest, err)
	}

	sigByLayer := make(map[string]ocispec.Descriptor, len(sigManifest.Layers))
	for i, sig := range sigManifest.Layers {
		layerDigest := sig.Annotations[dmverity.AnnotationLayerDigest]
		if layerDigest == "" || sig.Annotations[dmverity.AnnotationLayerRootHash] == "" {
			printer.PrintErrorf("Warning: signature #%d (%s) is missing dm-verity annotations; skipping\n", i, sig.Digest)
			continue
		}
		if prev, exists := sigByLayer[layerDigest]; exists {
			return fmt.Errorf("dm-verity referrer contains multiple signatures for layer %s (%s and %s)", layerDigest, prev.Digest, sig.Digest)
		}
		sigByLayer[layerDigest] = sig
	}

	printer.PrintErrorf("Verifying %d dm-verity layer signature(s) for %s (note: image manifest signature is NOT checked; run `notation verify` separately for that)\n", len(sigManifest.Layers), resolvedRef)
	if opts.noRecompute {
		printer.PrintErrorf("Warning: --no-recompute proves only that a trusted signer signed SOME root hash; it does NOT prove the signed hash matches the layer.\n")
	}

	verifier := &dmverity.LayerVerifier{
		Roots:     roots,
		Recompute: !opts.noRecompute,
	}

	pass, fail := 0, 0
	for _, layer := range imageManifest.Layers {
		res := verifyLayer(ctx, verifier, fetcher, layer, sigByLayer, opts.noRecompute)
		if res.Err == nil {
			pass++
			printer.PrintErrorf("PASS %s\n", res.LayerDigest)
			continue
		}
		fail++
		printer.PrintErrorf("FAIL %s: %s\n", res.LayerDigest, res.Err)
	}

	total := len(imageManifest.Layers)
	if fail == 0 {
		printer.PrintErrorf("PASS: %d/%d dm-verity layer signatures verified\n", pass, total)
		return nil
	}
	return fmt.Errorf("dm-verity verification failed: %d/%d layers failed", fail, total)
}

// verifyLayer fetches the per-layer signature blob (and layer blob, when
// recomputing) and dispatches to the LayerVerifier.
func verifyLayer(ctx context.Context, v *dmverity.LayerVerifier, fetcher *registryutil.BlobFetcher, layer ocispec.Descriptor, sigByLayer map[string]ocispec.Descriptor, noRecompute bool) dmverity.LayerVerifyResult {
	digestStr := layer.Digest.String()
	sigDesc, ok := sigByLayer[digestStr]
	if !ok {
		return dmverity.LayerVerifyResult{
			LayerDigest: digestStr,
			Err:         errors.New("no dm-verity signature found in the referrer for this layer"),
		}
	}
	annotatedHash := sigDesc.Annotations[dmverity.AnnotationLayerRootHash]

	pkcs7Sig, err := fetcher.FetchBlob(ctx, sigDesc)
	if err != nil {
		return dmverity.LayerVerifyResult{
			LayerDigest:   digestStr,
			AnnotatedHash: annotatedHash,
			Err:           fmt.Errorf("failed to fetch signature blob %s: %w", sigDesc.Digest, err),
		}
	}

	var layerBlob []byte
	if !noRecompute {
		layerBlob, err = fetcher.FetchBlob(ctx, layer)
		if err != nil {
			return dmverity.LayerVerifyResult{
				LayerDigest:   digestStr,
				AnnotatedHash: annotatedHash,
				Err:           fmt.Errorf("failed to fetch layer blob %s: %w", layer.Digest, err),
			}
		}
	}

	return v.VerifyLayerSignature(ctx, digestStr, layerBlob, annotatedHash, pkcs7Sig)
}

// findDmverityReferrer locates the single dm-verity signature referrer for
// subject via the OCI Distribution Spec v1.1 Referrers API.
func findDmverityReferrer(ctx context.Context, repo *remote.Repository, subject ocispec.Descriptor) (ocispec.Descriptor, error) {
	var refs []ocispec.Descriptor
	err := repo.Referrers(ctx, subject, dmverity.ReferrerArtifactType, func(page []ocispec.Descriptor) error {
		refs = append(refs, page...)
		return nil
	})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to list referrers for %s (the registry may not support the OCI Referrers API): %w", subject.Digest, err)
	}
	switch len(refs) {
	case 0:
		return ocispec.Descriptor{}, fmt.Errorf("no dm-verity signatures found for %s (no referrer with artifactType %q)", subject.Digest, dmverity.ReferrerArtifactType)
	case 1:
		return refs[0], nil
	default:
		digests := make([]string, len(refs))
		for i, r := range refs {
			digests[i] = r.Digest.String()
		}
		return ocispec.Descriptor{}, fmt.Errorf("ambiguous: %d dm-verity referrers found for %s (%s)", len(refs), subject.Digest, strings.Join(digests, ", "))
	}
}

// isImageManifest returns true for OCI and Docker image manifest media
// types and false for index/list types.
func isImageManifest(mt string) bool {
	return mt == ocispec.MediaTypeImageManifest || mt == "application/vnd.docker.distribution.manifest.v2+json"
}
