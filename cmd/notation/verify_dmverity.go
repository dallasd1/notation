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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/notaryproject/notation/v2/internal/dmverity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

// dmverityReferrerArtifactType identifies the dm-verity layer-signature
// referrer manifest produced by `notation sign --dm-verity`.
const dmverityReferrerArtifactType = "application/vnd.cncf.notary.dmverity.v1"

// dm-verity signature descriptor annotation keys (mirror what sign.go
// produces in internal/dmverity.CreateSignatureManifest).
const (
	annLayerDigest   = "io.cncf.notary.dmverity.layer-digest"
	annLayerRootHash = "io.cncf.notary.dmverity.layer-roothash"
)

// runVerifyDmVerity verifies dm-verity PKCS#7 layer signatures for the image
// at opts.reference, against the CA pool loaded from opts.caPath.
//
// Scope: this command verifies layer signatures ONLY. The image manifest's
// notation signature (JWS/COSE) is NOT verified by this command; run
// `notation verify` (without --dm-verity) to check that separately.
func runVerifyDmVerity(ctx context.Context, opts *verifyOpts) error {
	roots, err := dmverity.LoadCAPool(opts.caPath)
	if err != nil {
		return err
	}

	ref, err := registry.ParseReference(opts.reference)
	if err != nil {
		return fmt.Errorf("invalid reference %q: %w", opts.reference, err)
	}
	if ref.Reference == "" {
		return fmt.Errorf("reference %q has no tag or digest", opts.reference)
	}

	remoteRepo, err := getRepositoryClient(ctx, &opts.SecureFlagOpts, ref)
	if err != nil {
		return fmt.Errorf("create repository client: %w", err)
	}

	subjectDesc, err := remoteRepo.Resolve(ctx, ref.Reference)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", opts.reference, err)
	}
	if !isImageManifestMediaType(subjectDesc.MediaType) {
		return fmt.Errorf("dm-verity verify requires an image manifest, but %q resolves to %s; pass a digest that names a specific platform manifest, not an image index", opts.reference, subjectDesc.MediaType)
	}

	sigManifestDesc, err := findDmverityReferrer(ctx, remoteRepo, subjectDesc)
	if err != nil {
		return err
	}

	sigManifest, err := fetchManifest(ctx, remoteRepo, sigManifestDesc)
	if err != nil {
		return fmt.Errorf("fetch dm-verity signature manifest %s: %w", sigManifestDesc.Digest, err)
	}

	imageManifest, err := fetchManifest(ctx, remoteRepo, subjectDesc)
	if err != nil {
		return fmt.Errorf("fetch image manifest %s: %w", subjectDesc.Digest, err)
	}

	sigByLayer, warnings, err := indexSignaturesByLayer(sigManifest.Layers)
	if err != nil {
		return err
	}

	resolvedRef := fmt.Sprintf("%s/%s@%s", ref.Registry, ref.Repository, subjectDesc.Digest)
	out := os.Stderr

	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "Verifying dm-verity layer signatures for %s\n", resolvedRef)
	fmt.Fprintln(out, "NOTE: this command verifies dm-verity layer PKCS#7 signatures only.")
	fmt.Fprintln(out, "      The image manifest signature is NOT verified by this command;")
	fmt.Fprintln(out, "      run `notation verify` (without --dm-verity) for that.")
	fmt.Fprintf(out, "dm-verity referrer: %s (%d signatures)\n", sigManifestDesc.Digest, len(sigManifest.Layers))
	if opts.noRecompute {
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "WARNING: --no-recompute is set. This run proves only that a trusted signer signed")
		fmt.Fprintln(out, "         SOME root hash for each layer; it does NOT prove the signed root hash")
		fmt.Fprintln(out, "         belongs to the OCI layer at that digest. Re-run without --no-recompute")
		fmt.Fprintln(out, "         (default) for full kernel-equivalent integrity.")
	}
	for _, w := range warnings {
		fmt.Fprintf(out, "Warning: %s\n", w)
	}
	fmt.Fprintln(out, "")

	verifier := &dmverity.LayerVerifier{
		Roots:              roots,
		Recompute:          !opts.noRecompute,
		RequireCodeSignEKU: true,
	}

	results := make([]dmverity.LayerVerifyResult, 0, len(imageManifest.Layers))
	for _, layer := range imageManifest.Layers {
		sigDesc, ok := sigByLayer[layer.Digest.String()]
		if !ok {
			results = append(results, dmverity.LayerVerifyResult{
				LayerDigest: layer.Digest.String(),
				Status:      dmverity.StatusFail,
				Err:         errors.New("no dm-verity signature found for this layer in the referrer"),
			})
			continue
		}
		annotatedHash := sigDesc.Annotations[annLayerRootHash]

		pkcs7Sig, err := fetchBlobBytes(ctx, remoteRepo, sigDesc)
		if err != nil {
			results = append(results, dmverity.LayerVerifyResult{
				LayerDigest:   layer.Digest.String(),
				AnnotatedHash: annotatedHash,
				Status:        dmverity.StatusFail,
				Err:           fmt.Errorf("fetch signature blob %s: %w", sigDesc.Digest, err),
			})
			continue
		}

		var layerBlob []byte
		if !opts.noRecompute {
			layerBlob, err = fetchBlobBytes(ctx, remoteRepo, layer)
			if err != nil {
				results = append(results, dmverity.LayerVerifyResult{
					LayerDigest:   layer.Digest.String(),
					AnnotatedHash: annotatedHash,
					Status:        dmverity.StatusFail,
					Err:           fmt.Errorf("fetch layer blob %s: %w", layer.Digest, err),
				})
				continue
			}
		}

		res := verifier.VerifyLayerSignature(ctx, layer.Digest.String(), layerBlob, annotatedHash, pkcs7Sig)
		results = append(results, res)
	}

	return reportDmverityResults(out, results)
}

// findDmverityReferrer locates the single dm-verity signature referrer for
// `subject` via the Referrers API. Returns descriptive errors when:
//   - zero referrers with the dm-verity artifact type are found
//   - more than one referrer is found (ambiguous; v1 does not select)
//   - the registry call fails (could be unsupported Referrers API or other
//     transport-level errors)
func findDmverityReferrer(ctx context.Context, repo *remote.Repository, subject ocispec.Descriptor) (ocispec.Descriptor, error) {
	var refs []ocispec.Descriptor
	err := repo.Referrers(ctx, subject, dmverityReferrerArtifactType, func(page []ocispec.Descriptor) error {
		refs = append(refs, page...)
		return nil
	})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("list referrers for %s: %w (the registry may not support the OCI Distribution Spec v1.1 Referrers API)", subject.Digest, err)
	}
	if len(refs) == 0 {
		return ocispec.Descriptor{}, fmt.Errorf("no dm-verity signatures found for %s (no referrer with artifactType %q)", subject.Digest, dmverityReferrerArtifactType)
	}
	if len(refs) > 1 {
		digests := make([]string, 0, len(refs))
		for _, r := range refs {
			digests = append(digests, r.Digest.String())
		}
		return ocispec.Descriptor{}, fmt.Errorf("ambiguous: %d dm-verity referrers found for %s (%s); v1 does not select between them", len(refs), subject.Digest, strings.Join(digests, ", "))
	}
	return refs[0], nil
}

// fetchManifest fetches a manifest descriptor's content and unmarshals it as
// an ocispec.Manifest. (Both the image manifest and the dm-verity signature
// referrer use the same schema; we only ever consume their Layers slice.)
func fetchManifest(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
	rc, err := repo.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest %s: %w", desc.Digest, err)
	}
	return &m, nil
}

// fetchBlobBytes fetches the bytes of an OCI blob by descriptor.
func fetchBlobBytes(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor) ([]byte, error) {
	rc, err := repo.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// indexSignaturesByLayer pairs each dm-verity signature descriptor to an
// image layer digest via the `io.cncf.notary.dmverity.layer-digest`
// annotation. Returns descriptive errors on duplicate pairings (ambiguous)
// and informational warnings (non-fatal) for descriptors missing required
// annotations.
func indexSignaturesByLayer(sigs []ocispec.Descriptor) (map[string]ocispec.Descriptor, []string, error) {
	out := make(map[string]ocispec.Descriptor, len(sigs))
	var warnings []string
	for i, sig := range sigs {
		layerDigest := sig.Annotations[annLayerDigest]
		if layerDigest == "" {
			warnings = append(warnings, fmt.Sprintf("signature descriptor #%d (%s) is missing %q annotation; skipping", i, sig.Digest, annLayerDigest))
			continue
		}
		if sig.Annotations[annLayerRootHash] == "" {
			warnings = append(warnings, fmt.Sprintf("signature descriptor #%d (%s) is missing %q annotation; skipping", i, sig.Digest, annLayerRootHash))
			continue
		}
		if prev, exists := out[layerDigest]; exists {
			return nil, nil, fmt.Errorf("ambiguous: dm-verity referrer contains multiple signatures for layer %s (descriptors %s and %s)", layerDigest, prev.Digest, sig.Digest)
		}
		out[layerDigest] = sig
	}
	return out, warnings, nil
}

// reportDmverityResults prints a per-layer table and returns a non-nil error
// (causing exit-code != 0) iff any layer failed.
func reportDmverityResults(w io.Writer, results []dmverity.LayerVerifyResult) error {
	const layerCol = 72
	const hashCol = 64
	fmt.Fprintf(w, "%-*s  %-*s  STATUS\n", layerCol, "LAYER", hashCol, "ROOT HASH")
	fmt.Fprintln(w, strings.Repeat("-", layerCol+2+hashCol+2+6))
	pass, fail := 0, 0
	for _, r := range results {
		hash := r.ComputedHash
		if hash == "" {
			hash = r.AnnotatedHash
		}
		if hash == "" {
			hash = "(unavailable)"
		}
		status := string(r.Status)
		if r.Err != nil {
			status = fmt.Sprintf("%s (%s)", r.Status, firstLine(r.Err.Error()))
		}
		fmt.Fprintf(w, "%-*s  %-*s  %s\n", layerCol, truncate(r.LayerDigest, layerCol), hashCol, truncate(hash, hashCol), status)
		if r.Status == dmverity.StatusPass {
			pass++
		} else {
			fail++
		}
	}
	fmt.Fprintln(w, "")
	if fail == 0 {
		fmt.Fprintf(w, "PASS: %d/%d dm-verity signatures verified\n", pass, len(results))
		return nil
	}
	fmt.Fprintf(w, "FAIL: %d/%d dm-verity signatures verified; %d failed\n", pass, len(results), fail)
	return fmt.Errorf("dm-verity verification failed: %d/%d signatures invalid", fail, len(results))
}

// isImageManifestMediaType returns true for OCI image manifest and Docker
// image manifest v2 media types. Returns false for index/list types (which
// require a per-platform descent the caller must do explicitly).
func isImageManifestMediaType(mt string) bool {
	switch mt {
	case ocispec.MediaTypeImageManifest, "application/vnd.docker.distribution.manifest.v2+json":
		return true
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
