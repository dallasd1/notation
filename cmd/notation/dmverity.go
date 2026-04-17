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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/notaryproject/notation-go/log"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/flag"
	"github.com/notaryproject/notation/v2/internal/dmverity"
	"github.com/notaryproject/notation/v2/internal/registryutil"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"
)

// subjectFileName is the file written by 'prepare' and read by 'push' that
// contains the JSON-encoded ocispec.Descriptor of the original image manifest.
const subjectFileName = "subject.json"

// roothashExt is the extension for files containing either the raw root hash
// (after 'prepare') or the detached PKCS#7 signature (after external signing,
// before 'push'). The file contents are signed in place by the external signer.
const roothashExt = ".roothash"

// metaExt is the extension for sidecar metadata files (key=value format).
const metaExt = ".roothash.meta"

type dmverityPrepareOpts struct {
	flag.LoggingFlagOpts
	flag.SecureFlagOpts
	reference string
	outputDir string
}

type dmverityPushOpts struct {
	flag.LoggingFlagOpts
	flag.SecureFlagOpts
	reference      string
	signaturesDir  string
	manifestOutput string
}

func dmverityCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dmverity",
		Short: "[Experimental] dm-verity layer signing operations with detached signers",
		Long: `Detached dm-verity signing flow for use with external signers (HSM, KMS, ESRP, etc.).

The flow is split into two commands so that an external signer can run between them:

  1. notation dmverity prepare --image <ref> --output-dir <dir>
       Pulls the image manifest, computes a dm-verity root hash for each layer,
       and writes <layer-digest>.roothash (containing the hex root hash bytes),
       <layer-digest>.roothash.meta (sidecar key=value metadata), and subject.json
       (the OCI descriptor of the image manifest) into <dir>.

  2. (External step) Each *.roothash file is signed in place by the external
     signer, producing detached PKCS#7 (DER). The sidecar .meta files and
     subject.json are not modified.

  3. notation dmverity push --image <ref> --signatures-dir <dir>
       Reads the signed *.roothash files and their .meta sidecars, builds the
       OCI referrer manifest (artifactType application/vnd.cncf.notary.dmverity.v1)
       identical to that produced by 'notation sign --dm-verity', and pushes the
       signature blobs and manifest to the registry.`,
	}
	cmd.AddCommand(dmverityPrepareCommand(nil), dmverityPushCommand(nil))
	return cmd
}

func dmverityPrepareCommand(opts *dmverityPrepareOpts) *cobra.Command {
	if opts == nil {
		opts = &dmverityPrepareOpts{}
	}
	cmd := &cobra.Command{
		Use:   "prepare [reference]",
		Short: "[Experimental] compute dm-verity root hashes for an image's layers",
		Long: `Pulls the image manifest, computes a dm-verity root hash for each layer,
and writes the hashes plus sidecar metadata into --output-dir for an external
signer to sign in place.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.reference = args[0]
			return runDmverityPrepare(cmd, opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(cmd.Flags())
	opts.SecureFlagOpts.ApplyFlags(cmd.Flags())
	cmd.Flags().StringVarP(&opts.outputDir, "output-dir", "o", "", "directory to write *.roothash, *.roothash.meta, and subject.json (required)")
	_ = cmd.MarkFlagRequired("output-dir")
	return cmd
}

func dmverityPushCommand(opts *dmverityPushOpts) *cobra.Command {
	if opts == nil {
		opts = &dmverityPushOpts{}
	}
	cmd := &cobra.Command{
		Use:   "push [reference]",
		Short: "[Experimental] push a dm-verity OCI referrer manifest from externally-signed root hashes",
		Long: `Reads *.roothash files (now containing detached PKCS#7 signatures from an
external signer) and their .roothash.meta sidecars from --signatures-dir, builds
the OCI referrer manifest, and pushes signature blobs and the manifest to the
registry.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.reference = args[0]
			return runDmverityPush(cmd, opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(cmd.Flags())
	opts.SecureFlagOpts.ApplyFlags(cmd.Flags())
	cmd.Flags().StringVarP(&opts.signaturesDir, "signatures-dir", "s", "", "directory containing signed *.roothash files, *.roothash.meta sidecars, and subject.json (required)")
	cmd.Flags().StringVar(&opts.manifestOutput, "manifest-output", "", "if set, write the OCI referrer manifest JSON to this path before pushing (useful for debugging or when push may fail)")
	_ = cmd.MarkFlagRequired("signatures-dir")
	return cmd
}

func runDmverityPrepare(command *cobra.Command, opts *dmverityPrepareOpts) error {
	ctx := opts.LoggingFlagOpts.InitializeLogger(command.Context())
	logger := log.GetLogger(ctx)

	if err := os.MkdirAll(opts.outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
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
		return fmt.Errorf("failed to create blob fetcher: %w", err)
	}

	manifestDesc, err := remoteRepo.Resolve(ctx, opts.reference)
	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", opts.reference, err)
	}
	manifest, err := fetcher.FetchManifest(ctx, manifestDesc)
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}

	subjectPath := filepath.Join(opts.outputDir, subjectFileName)
	subjectJSON, err := json.MarshalIndent(manifestDesc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal subject descriptor: %w", err)
	}
	if err := os.WriteFile(subjectPath, subjectJSON, 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", subjectFileName, err)
	}
	logger.Debugf("wrote subject descriptor: %s (%s, %d bytes)", manifestDesc.Digest, manifestDesc.MediaType, manifestDesc.Size)

	for _, layer := range manifest.Layers {
		layerData, err := fetcher.FetchBlob(ctx, layer)
		if err != nil {
			return fmt.Errorf("failed to fetch layer %s: %w", layer.Digest, err)
		}
		rootHash, err := dmverity.ComputeRootHash(layerData)
		if err != nil {
			return fmt.Errorf("failed to compute root hash for layer %s: %w", layer.Digest, err)
		}

		safe := safeDigest(layer.Digest.String())
		hashPath := filepath.Join(opts.outputDir, safe+roothashExt)
		metaPath := filepath.Join(opts.outputDir, safe+metaExt)

		// The .roothash file is the payload an external signer will sign in place.
		// Contents must match exactly what notation's local signer hashes:
		// []byte(rootHash) where rootHash is the hex string returned by ComputeRootHash.
		if err := os.WriteFile(hashPath, []byte(rootHash), 0o644); err != nil {
			return fmt.Errorf("failed to write %s: %w", hashPath, err)
		}

		metaContent := fmt.Sprintf("layer_digest=%s\nlayer_size=%d\nroot_hash=%s\n", layer.Digest, layer.Size, rootHash)
		if err := os.WriteFile(metaPath, []byte(metaContent), 0o644); err != nil {
			return fmt.Errorf("failed to write %s: %w", metaPath, err)
		}

		fmt.Fprintf(command.OutOrStdout(), "%s %s\n", layer.Digest, rootHash)
	}

	fmt.Fprintf(command.ErrOrStderr(), "Wrote %d root hashes to %s\n", len(manifest.Layers), opts.outputDir)
	return nil
}

func runDmverityPush(command *cobra.Command, opts *dmverityPushOpts) error {
	ctx := opts.LoggingFlagOpts.InitializeLogger(command.Context())

	subjectPath := filepath.Join(opts.signaturesDir, subjectFileName)
	subjectBytes, err := os.ReadFile(subjectPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", subjectFileName, err)
	}
	var subject ocispec.Descriptor
	if err := json.Unmarshal(subjectBytes, &subject); err != nil {
		return fmt.Errorf("failed to parse %s: %w", subjectFileName, err)
	}

	entries, err := os.ReadDir(opts.signaturesDir)
	if err != nil {
		return fmt.Errorf("failed to read signatures directory: %w", err)
	}

	var signatures []dmverity.SignatureEnvelope
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), roothashExt) || strings.HasSuffix(e.Name(), metaExt) {
			continue
		}
		base := strings.TrimSuffix(e.Name(), roothashExt)

		sigBytes, err := os.ReadFile(filepath.Join(opts.signaturesDir, e.Name()))
		if err != nil {
			return fmt.Errorf("failed to read signature %s: %w", e.Name(), err)
		}
		meta, err := readMetaFile(filepath.Join(opts.signaturesDir, base+metaExt))
		if err != nil {
			return fmt.Errorf("failed to read meta for %s: %w", e.Name(), err)
		}
		layerDigest := meta["layer_digest"]
		rootHash := meta["root_hash"]
		if layerDigest == "" || rootHash == "" {
			return fmt.Errorf("meta for %s missing layer_digest or root_hash", e.Name())
		}

		signatures = append(signatures, dmverity.SignatureEnvelope{
			LayerDigest: layerDigest,
			RootHash:    rootHash,
			Signature:   sigBytes,
		})
	}
	if len(signatures) == 0 {
		return fmt.Errorf("no %s files found in %s", roothashExt, opts.signaturesDir)
	}

	sigManifest, err := dmverity.CreateSignatureManifest(signatures, subject)
	if err != nil {
		return fmt.Errorf("failed to create signature manifest: %w", err)
	}

	if opts.manifestOutput != "" {
		manifestJSON, err := json.MarshalIndent(sigManifest, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal signature manifest: %w", err)
		}
		if err := os.WriteFile(opts.manifestOutput, manifestJSON, 0o644); err != nil {
			return fmt.Errorf("failed to write manifest output: %w", err)
		}
		fmt.Fprintf(command.ErrOrStderr(), "Wrote manifest JSON to %s\n", opts.manifestOutput)
	}

	ref, err := registry.ParseReference(opts.reference)
	if err != nil {
		return fmt.Errorf("failed to parse reference: %w", err)
	}
	remoteRepo, err := getRepositoryClient(ctx, &opts.SecureFlagOpts, ref)
	if err != nil {
		return fmt.Errorf("failed to get repository client: %w", err)
	}

	desc, err := pushDmVerityManifest(ctx, remoteRepo, sigManifest, signatures)
	if err != nil {
		return fmt.Errorf("failed to push dm-verity manifest: %w", err)
	}

	fmt.Fprintf(command.ErrOrStderr(), "Pushed dm-verity referrer manifest %s (subject %s)\n", desc.Digest, subject.Digest)
	return nil
}

// safeDigest converts "sha256:abc" -> "sha256-abc" for use in filenames.
func safeDigest(d string) string {
	return strings.ReplaceAll(d, ":", "-")
}

// readMetaFile parses a key=value file, ignoring blank lines and lines starting with '#'.
func readMetaFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
