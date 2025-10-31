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
// Output: EROFS filesystem image as bytes
//
// Process:
// 1. Decompress gzip to get tar
// 2. Extract tar to temporary directory
// 3. Run mkfs.erofs to create EROFS image
// 4. Read EROFS image bytes
// 5. Clean up temporary files
//
// This is a general-purpose conversion utility that can be used by any component
// needing EROFS conversion (not specific to dm-verity signing).
func (c *Converter) ConvertLayerToEROFS(ctx context.Context, layerData []byte) ([]byte, error) {
// Create temporary directory for extraction
extractDir, err := os.MkdirTemp(c.TempDir, "erofs-extract-*")
if err != nil {
return nil, fmt.Errorf("failed to create temp extraction directory: %w", err)
}
defer os.RemoveAll(extractDir)

// Decompress and extract the tar.gz layer
fmt.Printf("[erofs.Converter] Decompressing %d bytes of gzip data...\n", len(layerData))
if err := c.extractTarGz(layerData, extractDir); err != nil {
return nil, fmt.Errorf("failed to extract layer tarball: %w", err)
}

// Create EROFS image from extracted files
fmt.Printf("[erofs.Converter] Creating EROFS image from extracted files...\n")
erofsData, err := c.createEROFSImage(ctx, extractDir)
if err != nil {
return nil, fmt.Errorf("failed to create EROFS image: %w", err)
}

fmt.Printf("[erofs.Converter] Successfully created EROFS image: %d bytes\n", len(erofsData))
return erofsData, nil
}

// extractTarGz decompresses and extracts a tar.gz byte stream to a directory
func (c *Converter) extractTarGz(compressedData []byte, destDir string) error {
// Decompress gzip
gzReader, err := gzip.NewReader(bytes.NewReader(compressedData))
if err != nil {
return fmt.Errorf("failed to create gzip reader: %w", err)
}
defer gzReader.Close()

// Use tar command to extract (more robust than Go's tar package for various tar formats)
cmd := exec.Command("tar", "-xf", "-", "-C", destDir)
cmd.Stdin = gzReader

var stderr bytes.Buffer
cmd.Stderr = &stderr

if err := cmd.Run(); err != nil {
return fmt.Errorf("tar extraction failed: %w, stderr: %s", err, stderr.String())
}

return nil
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

// mkfs.erofs <output_image> <source_directory>
cmd := exec.CommandContext(cmdCtx, "mkfs.erofs", erofsPath, sourceDir)

var stdout, stderr bytes.Buffer
cmd.Stdout = &stdout
cmd.Stderr = &stderr

fmt.Printf("[erofs.Converter] Running: mkfs.erofs %s %s\n", erofsPath, sourceDir)

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
