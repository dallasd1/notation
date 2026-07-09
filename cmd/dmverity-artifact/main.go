// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0.

// Command dmverity-artifact materializes the precomputed EROFS and dm-verity
// outputs for one compressed OCI layer. It is used by external signing
// pipelines so they share the exact conversion implementation used by
// `notation sign --dm-verity`.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/notaryproject/notation/v2/internal/dmverity"
	"github.com/opencontainers/go-digest"
)

type artifactMetadata struct {
	SchemaVersion     int    `json:"schemaVersion"`
	SourceLayerDigest string `json:"sourceLayerDigest"`
	RootHash          string `json:"rootHash"`
	Layout            string `json:"layout"`
}

func main() {
	var layerDigest string
	var inputPath string
	var outputDir string

	flag.StringVar(&layerDigest, "layer-digest", "", "source OCI layer digest")
	flag.StringVar(&inputPath, "input", "", "compressed OCI layer blob")
	flag.StringVar(&outputDir, "output-dir", "", "directory for generated artifacts")
	flag.Parse()

	if err := run(layerDigest, inputPath, outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "dmverity-artifact: %v\n", err)
		os.Exit(1)
	}
}

func run(layerDigest, inputPath, outputDir string) error {
	parsedDigest, err := digest.Parse(layerDigest)
	if err != nil {
		return fmt.Errorf("invalid --layer-digest: %w", err)
	}
	if inputPath == "" {
		return fmt.Errorf("--input is required")
	}
	if outputDir == "" {
		return fmt.Errorf("--output-dir is required")
	}

	layerData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read layer: %w", err)
	}
	if err := parsedDigest.Validate(); err != nil {
		return fmt.Errorf("invalid --layer-digest: %w", err)
	}
	if got := digest.FromBytes(layerData); got != parsedDigest {
		return fmt.Errorf("layer digest mismatch: input is %s, expected %s", got, parsedDigest)
	}

	artifact, err := dmverity.ComputeLayerArtifact(parsedDigest.String(), layerData)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	base := parsedDigest.Algorithm().String() + "-" + parsedDigest.Encoded()
	if err := os.WriteFile(filepath.Join(outputDir, base+".erofs"), artifact.EROFSData, 0644); err != nil {
		return fmt.Errorf("failed to write EROFS artifact: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, base+".hashtree"), artifact.MerkleTree, 0644); err != nil {
		return fmt.Errorf("failed to write Merkle-tree artifact: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, base+".roothash"), []byte(artifact.RootHash), 0644); err != nil {
		return fmt.Errorf("failed to write root hash: %w", err)
	}
	meta := []byte(fmt.Sprintf("%s\n%d\n", artifact.RootHash, len(artifact.EROFSData)))
	if err := os.WriteFile(filepath.Join(outputDir, base+".roothash.meta"), meta, 0644); err != nil {
		return fmt.Errorf("failed to write root-hash metadata: %w", err)
	}

	metadataJSON, err := json.MarshalIndent(artifactMetadata{
		SchemaVersion:     1,
		SourceLayerDigest: parsedDigest.String(),
		RootHash:          artifact.RootHash,
		Layout:            dmverity.SeparateHashDeviceLayout,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal artifact metadata: %w", err)
	}
	metadataJSON = append(metadataJSON, '\n')
	if err := os.WriteFile(filepath.Join(outputDir, base+".artifact.json"), metadataJSON, 0644); err != nil {
		return fmt.Errorf("failed to write artifact metadata: %w", err)
	}

	fmt.Printf("%s\n", artifact.RootHash)
	return nil
}
