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
// The package implements a "tar index mode" conversion using mkfs.erofs --tar=i, which
// creates EROFS metadata that references the original tar file rather than extracting it.

// The resulting EROFS image consists of:
//  EROFS metadata, original tar data appended after metadata, and
//  512-byte alignment padding for dm-verity block device compatibility
//
// This implementation MUST match containerd's erofs-snapshotter to ensure
// compatible dm-verity root hash calculations.

package erofs

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

const (
	// mkfsErofsTimeout is the maximum time allowed for mkfs.erofs to complete.
	mkfsErofsTimeout = 5 * time.Minute
	// blockAlignment is the dm-verity data block size we align to for deterministic hashing.
	// Must match erofs-snapshotter's EROFS_BLOCK_ALIGNMENT constant (512 bytes).
	blockAlignment = 512
	// fixedMetadataUUID is the deterministic UUID used for tar index EROFS builds.
	// Must match erofs-snapshotter's EROFS_METADATA_UUID constant.
	fixedMetadataUUID = "c1b9d5a2-f162-11cf-9ece-0020afc76f16"
)

// Converter provides EROFS filesystem conversion capabilities.
// Uses tar-index mode for compatibility with erofs-snapshotter.
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
// 4. Align to 512-byte boundary for dm-verity
// 5. Return combined (EROFS metadata + tar) data
func (c *Converter) ConvertLayerToEROFS(ctx context.Context, layerData []byte) ([]byte, error) {
	if len(layerData) == 0 {
		return nil, fmt.Errorf("layer data is empty")
	}

	// Decompress gzip to get raw tar
	tarData, err := c.decompressGzip(layerData)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}

	// Create EROFS metadata with tar index mode
	erofsData, err := c.createEROFSMetadataWithTar(ctx, tarData)
	if err != nil {
		return nil, fmt.Errorf("failed to create EROFS metadata: %w", err)
	}

	return erofsData, nil
}

// decompressGzip decompresses gzip data to raw tar bytes
func (c *Converter) decompressGzip(compressedData []byte) ([]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return nil, fmt.Errorf("layer data is not valid gzip (expected tar.gz layer): %w", err)
	}
	defer gzReader.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, gzReader); err != nil {
		return nil, fmt.Errorf("gzip decompression failed (corrupted layer data?): %w", err)
	}
	return buf.Bytes(), nil
}

// createEROFSMetadataWithTar creates EROFS metadata using --tar=i mode and appends the tar file.
func (c *Converter) createEROFSMetadataWithTar(ctx context.Context, tarData []byte) ([]byte, error) {
	// Check if mkfs.erofs is available
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		return nil, fmt.Errorf("mkfs.erofs not found in PATH: install 'erofs-utils' package (apt install erofs-utils / dnf install erofs-utils): %w", err)
	}

	// Write tar data to temporary file (mkfs.erofs needs a file path)
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

	// Run mkfs.erofs with erofs-snapshotter compatible flags
	cmdCtx, cancel := context.WithTimeout(ctx, mkfsErofsTimeout)
	defer cancel()

	// Match erofs-snapshotter's mkfs.erofs command:
	cmd := exec.CommandContext(cmdCtx, "mkfs.erofs",
		"--tar=i", // tar index mode
		"-T", "0", // Zero unix time
		"--mkfs-time",           // Clear mkfs time in superblock
		"-U", fixedMetadataUUID, // Fixed UUID for deterministic builds
		"--aufs",  // Convert OCI whiteouts to overlayfs metadata
		"--quiet", // Quiet mode
		erofsPath,
		tarPath,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mkfs.erofs failed: %w, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
	}

	// Read the EROFS metadata
	erofsMetadata, err := os.ReadFile(erofsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read EROFS metadata: %w", err)
	}

	// Append tar data to EROFS metadata
	combinedData := appendTarData(erofsMetadata, tarData)

	// Align to 512-byte boundary for dm-verity (matches erofs-snapshotter's EROFS_BLOCK_ALIGNMENT)
	alignedData := alignTo512(combinedData)

	return alignedData, nil
}

// appendTarData appends tar data to EROFS metadata
func appendTarData(erofsMetadata, tarData []byte) []byte {
	combined := make([]byte, len(erofsMetadata)+len(tarData))
	copy(combined, erofsMetadata)
	copy(combined[len(erofsMetadata):], tarData)
	return combined
}

// alignTo512 pads data to 512-byte boundary (matches erofs-snapshotter's EROFS_BLOCK_ALIGNMENT)
func alignTo512(data []byte) []byte {
	remainder := len(data) % blockAlignment
	if remainder == 0 {
		return data
	}

	paddingSize := blockAlignment - remainder
	aligned := make([]byte, len(data)+paddingSize)
	copy(aligned, data)
	// Zero padding (implicit in Go's make)
	return aligned
}
