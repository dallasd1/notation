package main

import (
	"context"
	"errors"
	"fmt"

	notationregistry "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/flag"
	"github.com/notaryproject/notation/v2/internal/dmverity"
	"github.com/notaryproject/notation/v2/internal/registryutil"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"
)

type verityOpts struct {
	flag.SecureFlagOpts
	reference         string
	forceReferrersTag bool
}

func verityCommand(opts *verityOpts) *cobra.Command {
	if opts == nil {
		opts = &verityOpts{}
	}

	cmd := &cobra.Command{
		Use:   "verity <reference>",
		Short: "Print dm-verity root hashes for image layers",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing reference to the artifact: use `notation verity --help`")
			}
			opts.reference = args[0]
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error { return runVerity(cmd, opts) },
	}

	opts.SecureFlagOpts.ApplyFlags(cmd.Flags())
	return cmd
}

func runVerity(cmd *cobra.Command, opts *verityOpts) error {
	ctx := context.Background()

	// Build remote repository client
	ref, err := registry.ParseReference(opts.reference)
	if err != nil {
		return fmt.Errorf("invalid reference %q: %w", opts.reference, err)
	}
	remoteRepo, err := getRepositoryClient(ctx, &opts.SecureFlagOpts, ref)
	if err != nil {
		return fmt.Errorf("failed to init remote repository: %w", err)
	}

	// Notation repository for resolving manifest descriptor
	sigRepo := notationregistry.NewRepository(remoteRepo)

	// Resolve to a digest manifest
	manifestDesc, resolvedRef, err := resolveReference(ctx, inputTypeRegistry, opts.reference, sigRepo, nil)
	if err != nil {
		return fmt.Errorf("failed to resolve reference: %w")
	}

	fmt.Printf("Resolved: %s\n", resolvedRef)

	// Fetch manifest using BlobFetcher
	fetcher, err := registryutil.NewBlobFetcher(ctx, resolvedRef, remoteRepo)
	if err != nil {
		return fmt.Errorf("failed to create blob fetcher: %w", err)
	}
	manifest, err := fetcher.FetchManifest(ctx, manifestDesc)
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}

	// Compute dm-verity root hashes per layer (without signing)
	fmt.Printf("Layers: %d\n", len(manifest.Layers))
	for i, layer := range manifest.Layers {
		fmt.Printf("- Layer %d digest: %s (size: %d)\n", i+1, layer.Digest.String(), layer.Size)
		data, err := fetcher.FetchBlob(ctx, layer)
		if err != nil {
			return fmt.Errorf("failed to fetch layer %s: %w", layer.Digest, err)
		}
		root, err := computeRootHash(data)
		if err != nil {
			return fmt.Errorf("failed to compute root hash for %s: %w", layer.Digest, err)
		}
		fmt.Printf("  Root hash: %s\n", root)
	}

	return nil
}

func computeRootHash(layerData []byte) (string, error) {
	// Compute dm-verity root hash over EROFS metadata + tar combined file.
	// This matches kata tardev-snapshotter production behavior:
	// 1. Decompress gzip → tar
	// 2. Create EROFS metadata with mkfs.erofs --tar=i
	// 3. Append tar to EROFS metadata
	// 4. Compute dm-verity tree with 512-byte blocks (append_tree function)
	//
	// The EROFS path uses the same mkfs.erofs args and block sizes as kata.
	return dmverity.ComputeRootHash(layerData)
}

// Wire command into root
func addVerityCommand(root *cobra.Command) {
	root.AddCommand(verityCommand(nil))
}
