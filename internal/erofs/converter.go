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
// This is a general-purpose package decoupled from any specific command logic (sign, verify, etc).
// It can be reused anywhere EROFS conversion is needed.
package erofs

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	// mkfsErofsTimeout is the maximum time allowed for mkfs.erofs to complete
	mkfsErofsTimeout = 5 * time.Minute
)

// Converter provides EROFS filesystem conversion capabilities.
// Decoupled from dm-verity logic - this is purely about tar -> EROFS conversion.
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
func (c *Converter) ConvertLayerToEROFS(ctx context.Context, layerData []byte) ([]byte, error) {
	// Decompress gzip to get raw tar
	fmt.Printf("[erofs.Converter] Decompressing %d bytes of gzip data...\n", len(layerData))
	tarData, err := c.decompressGzip(layerData)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}
	fmt.Printf("[erofs.Converter] Decompressed to %d bytes of tar data\n", len(tarData))

	// Create EROFS metadata + tar combined image
	fmt.Printf("[erofs.Converter] Creating EROFS metadata with tar index mode...\n")
	erofsData, err := c.createEROFSMetadataWithTar(ctx, tarData)
	if err != nil {
		return nil, fmt.Errorf("failed to create EROFS metadata: %w", err)
	}

	fmt.Printf("[erofs.Converter] Successfully created EROFS image: %d bytes\n", len(erofsData))
	return erofsData, nil
}

// decompressGzip decompresses gzip data to raw tar bytes
func (c *Converter) decompressGzip(compressedData []byte) ([]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, gzReader); err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}

	return buf.Bytes(), nil
}

// createEROFSMetadataWithTar creates EROFS metadata using --tar=i mode and appends the tar file.
func (c *Converter) createEROFSMetadataWithTar(ctx context.Context, tarData []byte) ([]byte, error) {
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
		"--mkfs-time",                                // Clear mkfs time
		"-U", "c1b9d5a2-f162-11cf-9ece-0020afc76f16", // Fixed UUID for determinism
		"--aufs",  // OCI whiteout conversion
		"--quiet", // Quiet mode
		erofsPath,
		tarPath,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Printf("[erofs.Converter] Running: mkfs.erofs --tar=i -T0 -U<uuid> --mkfs-time --aufs --quiet %s %s\n", filepath.Base(erofsPath), filepath.Base(tarPath))

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mkfs.erofs failed: %w, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
	}

	// Read EROFS metadata
	erofsMetadata, err := os.ReadFile(erofsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read EROFS metadata: %w", err)
	}

	// Append tar data to EROFS metadata
	fmt.Printf("[erofs.Converter] Appending %d bytes of tar to %d bytes of EROFS metadata\n", len(tarData), len(erofsMetadata))
	combined := append(erofsMetadata, tarData...)

	// Align to 512-byte boundary for proper block device alignment
	const blockAlignment = 512
	padding := (blockAlignment - (len(combined) % blockAlignment)) % blockAlignment
	if padding > 0 {
		combined = append(combined, make([]byte, padding)...)
		fmt.Printf("[erofs.Converter] Added %d bytes of padding to align to %d bytes\n", padding, blockAlignment)
	}

	return combined, nil
}

// createEROFSImage runs mkfs.erofs to create an EROFS filesystem image
func (c *Converter) createEROFSImage(ctx context.Context, sourceDir string) ([]byte, error) {
	// Check if mkfs.erofs is available
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		return nil, fmt.Errorf("mkfs.erofs not found in PATH (install erofs-utils package): %w", err)
	}

	// Create temporary file for EROFS output
	erofsFile, err := os.CreateTemp(c.TempDir, "erofs-image-*.img")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp EROFS file: %w", err)
	}
	erofsPath := erofsFile.Name()
	erofsFile.Close()
	defer os.Remove(erofsPath)

	// Run mkfs.erofs to create the filesystem
	cmdCtx, cancel := context.WithTimeout(ctx, mkfsErofsTimeout)
	defer cancel()

	// mkfs.erofs with reproducible build options:
	// -T0: Set fixed timestamp (epoch 0) for deterministic output
	// -U00000000-0000-0000-0000-000000000000: Fixed UUID for deterministic output
	// This ensures the same layer content always produces the same EROFS image
	cmd := exec.CommandContext(cmdCtx, "mkfs.erofs",
		"-T0",                                    // Fixed timestamp
		"-U00000000-0000-0000-0000-000000000000", // Fixed UUID
		erofsPath, sourceDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Printf("[erofs.Converter] Running: mkfs.erofs -T0 -U00000000... %s %s\n", erofsPath, sourceDir)

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mkfs.erofs failed: %w, stdout: %s, stderr: %s", err, stdout.String(), stderr.String())
	}

	// Read the EROFS image
	erofsData, err := os.ReadFile(erofsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read EROFS image: %w", err)
	}

	return erofsData, nil
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
func WriteToFile(erofsData []byte, outputPath string) error {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(outputPath, erofsData, 0644); err != nil {
		return fmt.Errorf("failed to write EROFS file: %w", err)
	}

	return nil
}

// ConvertLayerToEROFSFile converts a layer and writes directly to a file (avoids loading into memory)
func (c *Converter) ConvertLayerToEROFSFile(ctx context.Context, layerData []byte, outputPath string) error {
	erofsData, err := c.ConvertLayerToEROFS(ctx, layerData)
	if err != nil {
		return err
	}

	return WriteToFile(erofsData, outputPath)
}

// ConvertLayerStreamToEROFS converts a streaming layer (useful for large layers)
func (c *Converter) ConvertLayerStreamToEROFS(ctx context.Context, layerStream io.Reader) ([]byte, error) {
	// Read stream into bytes (for now - could be optimized for streaming in future)
	layerData, err := io.ReadAll(layerStream)
	if err != nil {
		return nil, fmt.Errorf("failed to read layer stream: %w", err)
	}

	return c.ConvertLayerToEROFS(ctx, layerData)
}
