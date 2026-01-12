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

// Package erofs provides utilities for converting OCI layer tarballs to EROFS filesystem format.
// EROFS (Enhanced Read-Only File System) is a lightweight, high-performance read-only filesystem
// designed for container images and other read-only workloads.
//
// The package implements a "tar index mode" conversion strategy using mkfs.erofs --tar=i, which
// creates EROFS metadata that references the original tar file rather than extracting it.
// This approach offers several advantages:
//   - Faster conversion (no tar extraction required)
//   - Lower memory usage (streaming tar data directly)
//   - Better compatibility with container runtimes that expect tar layers
//   - Maintains original tar structure for tools that need it
//
// The resulting EROFS image consists of:
//  1. EROFS metadata (filesystem structure, inodes, etc.)
//  2. Original tar data appended after metadata
//  3. 512-byte alignment padding for block device compatibility
//
// This design allows container runtimes to mount the EROFS filesystem while still
// having access to the underlying tar data when needed.
//
// Example usage:
//
//	converter := erofs.NewConverter("")
//	erofsData, err := converter.ConvertLayerToEROFS(ctx, gzippedLayerBytes)
//	if err != nil {
//	    return err
//	}
//	// erofsData now contains the EROFS filesystem image
//
// This is a general-purpose package decoupled from any specific command logic (sign, verify, etc).
// It can be reused anywhere EROFS conversion is needed.
package erofs

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/google/uuid"
)

const (
	// mkfsErofsTimeout is the maximum time allowed for mkfs.erofs to complete.
	mkfsErofsTimeout = 5 * time.Minute
	// blockAlignment is the dm-verity data block size we align to for deterministic hashing.
	blockAlignment = 512
)

// Converter provides EROFS filesystem conversion capabilities.
type Converter struct {
	// TempDir is the directory for temporary file operations
	// If empty, os.TempDir() will be used
	TempDir string
}

// NewConverter creates a new EROFS converter instance
func NewConverter(tempDir string) *Converter {
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &Converter{
		TempDir: tempDir,
	}
}

// ConvertLayerToEROFS converts a compressed OCI layer (tar.gz) to EROFS format.
//
// Input: layerData - compressed tar.gz bytes from registry
// Output: EROFS metadata + tar combined image as bytes
//
// Process:
// 1. Decompress gzip to get raw tar
// 2. Create EROFS metadata using mkfs.erofs --tar=i (tar index mode)
// 3. Append the raw tar file to EROFS metadata
// 4. Align to 512-byte boundary
// 5. Return combined (EROFS metadata + tar) data
func (c *Converter) ConvertLayerToEROFS(ctx context.Context, layerData []byte, layerDigest string) ([]byte, error) {
	// Decompress gzip to get raw tar
	fmt.Printf("[erofs.Converter] Decompressing %d bytes of gzip data...\n", len(layerData))
	tarData, err := c.decompressGzip(layerData)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}
	fmt.Printf("[erofs.Converter] Decompressed to %d bytes of tar data\n", len(tarData))

	// DEBUG: Save decompressed tar
	if debugErr := os.WriteFile("/tmp/notation_debug.tar", tarData, 0644); debugErr == nil {
		fmt.Printf("[erofs.Converter] DEBUG: Saved decompressed tar to /tmp/notation_debug.tar\n")
	}

	// Create EROFS metadata + tar combined image
	fmt.Printf("[erofs.Converter] Creating EROFS metadata with tar index mode...\n")
	layerUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+layerDigest)).String()
	fmt.Printf("[erofs.Converter] DEBUG: layerUUID=%s (from digest: %s)\n", layerUUID, layerDigest)
	erofsData, err := c.createEROFSMetadataWithTar(ctx, tarData, layerUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to create EROFS metadata: %w", err)
	}

	fmt.Printf("[erofs.Converter] Successfully created EROFS image: %d bytes\n", len(erofsData))
	return erofsData, nil
}

// DecompressGzipForTest exposes gzip decompression for testing/utility paths
// where we need raw tar without full EROFS conversion.
func (c *Converter) DecompressGzipForTest(compressedData []byte) ([]byte, error) {
	return c.decompressGzip(compressedData)
}

// decompressGzip decompresses gzip data to raw tar bytes
func (c *Converter) decompressGzip(compressedData []byte) ([]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(gzReader); err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}
	return buf.Bytes(), nil
}

// createEROFSMetadataWithTar creates EROFS metadata using --tar=i mode and appends the tar file.
func (c *Converter) createEROFSMetadataWithTar(ctx context.Context, tarData []byte, layerUUID string) ([]byte, error) {
	// Check if mkfs.erofs is available
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		return nil, fmt.Errorf("mkfs.erofs not found in PATH (install erofs-utils package): %w", err)
	}

	// Write tar data to temporary file
	tarFile, err := os.CreateTemp(c.TempDir, "layer-*.tar")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp tar file: %w", err)
	}
	tarPath := tarFile.Name()
	defer os.Remove(tarPath)

	if _, err := tarFile.Write(tarData); err != nil {
		tarFile.Close()
		return nil, fmt.Errorf("failed to write tar data: %w", err)
	}
	tarFile.Close()

	// Create temporary file for EROFS metadata output
	erofsFile, err := os.CreateTemp(c.TempDir, "erofs-metadata-*.img")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp EROFS file: %w", err)
	}
	erofsPath := erofsFile.Name()
	erofsFile.Close()
	defer os.Remove(erofsPath)

	// Run mkfs.erofs in tar index mode
	cmdCtx, cancel := context.WithTimeout(ctx, mkfsErofsTimeout)
	defer cancel()

	// mkfs.erofs flags for containerd compatibility:
	// --tar=i: tar index mode (creates EROFS metadata only, not full extraction)
	// -T 0: Zero out unix time for deterministic builds
	// --mkfs-time: Clear mkfs time in superblock
	// -U <UUID>: Use fixed UUID for deterministic builds
	// --aufs: Convert OCI whiteouts/opaque to overlayfs metadata
	// --quiet: Reduce output verbosity
	cmd := exec.CommandContext(cmdCtx, "mkfs.erofs",
		"--tar=i", // tar index mode
		"-T", "0", // Zero unix time
		"--mkfs-time",   // Clear mkfs time
		"-U", layerUUID, // Content-derived UUID (from layer digest)
		"--aufs",  // OCI whiteout conversion
		"--quiet", // Quiet mode
		erofsPath,
		tarPath,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Printf("[erofs.Converter] Running: %s\n", cmd.String())

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mkfs.erofs failed: %w, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
	}

	// Read EROFS metadata
	erofsMetadata, err := os.ReadFile(erofsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read EROFS metadata: %w", err)
	}
	fmt.Printf("[erofs.Converter] EROFS metadata size: %d bytes\n", len(erofsMetadata))

	// Append tar data after metadata to form the EROFS image body we hash/sign.
	combined := append(erofsMetadata, tarData...)
	fmt.Printf("[erofs.Converter] Combined (metadata + tar) size before padding: %d bytes\n", len(combined))

	// Align to blockAlignment boundary. dm-verity computes hashes over full blocks;
	// explicit zero padding removes ambiguity about tail handling and guarantees
	// producer & verifier derive identical Merkle roots.
	padding := (blockAlignment - (len(combined) % blockAlignment)) % blockAlignment
	if padding > 0 {
		combined = append(combined, make([]byte, padding)...)
		fmt.Printf("[erofs.Converter] Padded %d bytes (alignment %d)\n", padding, blockAlignment)
	}
	return combined, nil
}

// IsSupported checks if EROFS tools are available on the system
func IsSupported() (bool, error) {
	// Check for mkfs.erofs
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		return false, fmt.Errorf("mkfs.erofs not found (install erofs-utils package): %w", err)
	}

	// Check for tar
	if _, err := exec.LookPath("tar"); err != nil {
		return false, fmt.Errorf("tar not found: %w", err)
	}

	// Verify mkfs.erofs is functional
	cmd := exec.Command("mkfs.erofs", "--help")
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("mkfs.erofs not functional: %w", err)
	}

	return true, nil
}

// WriteToFile is a utility to write EROFS data to a file (useful for debugging/testing)
