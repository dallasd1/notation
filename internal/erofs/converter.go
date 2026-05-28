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

// Package erofs converts OCI layer tarballs to EROFS filesystem format
// using mkfs.erofs --tar=i (tar index mode). The output must match
// containerd's erofs-snapshotter for compatible dm-verity root hashes.
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

	"github.com/google/uuid"
)

const (
	mkfsErofsTimeout = 5 * time.Minute
	blockAlignment   = 512 // Must match erofs-snapshotter EROFS_BLOCK_ALIGNMENT
)

// erofsLayerUUID derives the same per-layer UUID containerd's erofs differ
// passes to mkfs.erofs (see containerd plugins/diff/erofs/differ.go), so the
// EROFS superblock notation produces here matches the one containerd produces
// at apply time. Identical superblocks -> identical dm-verity root hashes.
func erofsLayerUUID(layerDigest string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+layerDigest)).String()
}

// Converter converts OCI layers to EROFS using tar-index mode.
type Converter struct {
	TempDir string
}

// NewConverter creates a new EROFS converter. If tempDir is empty, os.TempDir() is used.
func NewConverter(tempDir string) *Converter {
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &Converter{
		TempDir: tempDir,
	}
}

// ConvertLayerToEROFS converts a compressed OCI layer (tar.gz) to EROFS format.
// layerDigest is the OCI manifest descriptor digest of the layer (e.g.
// "sha256:..."); it is used to derive the per-layer mkfs.erofs UUID so the
// output matches what containerd's erofs-snapshotter produces at apply time.
// Returns EROFS metadata + tar data, aligned to 512-byte boundary for dm-verity.
func (c *Converter) ConvertLayerToEROFS(ctx context.Context, layerDigest string, layerData []byte) ([]byte, error) {
	if layerDigest == "" {
		return nil, fmt.Errorf("layer digest is empty")
	}
	if len(layerData) == 0 {
		return nil, fmt.Errorf("layer data is empty")
	}

	tarData, err := c.decompressGzip(layerData)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress gzip: %w", err)
	}

	erofsData, err := c.buildEROFSImage(ctx, layerDigest, tarData)
	if err != nil {
		return nil, fmt.Errorf("failed to build EROFS image: %w", err)
	}

	return erofsData, nil
}

// decompressGzip decompresses gzip-compressed data and returns the raw tar data.
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

// buildEROFSImage creates an EROFS image from tar data using mkfs.erofs --tar=i.
// It generates EROFS metadata, appends the original tar data, and aligns the result
// to 512 bytes for dm-verity compatibility.
func (c *Converter) buildEROFSImage(ctx context.Context, layerDigest string, tarData []byte) ([]byte, error) {
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		return nil, fmt.Errorf("mkfs.erofs not found in PATH: install 'erofs-utils' package (apt install erofs-utils / dnf install erofs-utils): %w", err)
	}

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

	erofsFile, err := os.CreateTemp(c.TempDir, "erofs-metadata-*.img")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp EROFS file: %w", err)
	}
	erofsPath := erofsFile.Name()
	erofsFile.Close()
	defer os.Remove(erofsPath)

	cmdCtx, cancel := context.WithTimeout(ctx, mkfsErofsTimeout)
	defer cancel()

	// Flags must match erofs-snapshotter's mkfs.erofs invocation.
	// The -U UUID is derived per layer from the OCI digest the same way
	// containerd's erofs differ does it, so the superblock bytes (and thus
	// the dm-verity root hash) line up.
	cmd := exec.CommandContext(cmdCtx, "mkfs.erofs",
		"--tar=i", // tar index mode
		"-T", "0", // Zero unix time
		"--mkfs-time",                     // Clear mkfs time in superblock
		"-U", erofsLayerUUID(layerDigest), // Per-layer UUID matching containerd
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

	erofsMetadata, err := os.ReadFile(erofsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read EROFS metadata: %w", err)
	}

	combinedData := appendTarData(erofsMetadata, tarData)
	alignedData := alignTo512(combinedData)

	return alignedData, nil
}

func appendTarData(erofsMetadata, tarData []byte) []byte {
	combined := make([]byte, len(erofsMetadata)+len(tarData))
	copy(combined, erofsMetadata)
	copy(combined[len(erofsMetadata):], tarData)
	return combined
}

// alignTo512 pads data to 512-byte boundary for dm-verity.
func alignTo512(data []byte) []byte {
	remainder := len(data) % blockAlignment
	if remainder == 0 {
		return data
	}

	paddingSize := blockAlignment - remainder
	aligned := make([]byte, len(data)+paddingSize)
	copy(aligned, data)
	return aligned
}
