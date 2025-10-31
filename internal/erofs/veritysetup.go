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

// Veritysetup utilities for dm-verity root hash calculation
// Based on containerd PR #9: https://github.com/aadhar-agarwal/containerd/pull/9
package erofs

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	// veritysetupTimeout is the maximum time allowed for veritysetup to complete
	veritysetupTimeout = 5 * time.Minute
)

// VeritysetupOptions contains configuration for dm-verity operations
type VeritysetupOptions struct {
	// Salt for hashing (hex string, e.g., "0000...0000")
	Salt string
	// Hash algorithm (default: sha256)
	HashAlgorithm string
	// Data block size in bytes (default: 4096)
	DataBlockSize uint32
	// Hash block size in bytes (default: 4096)
	HashBlockSize uint32
	// Number of data blocks (calculated automatically if not set)
	DataBlocks uint64
	// Offset where hash tree begins (calculated automatically if not set)
	HashOffset uint64
} // DefaultVeritysetupOptions returns default dm-verity options
func DefaultVeritysetupOptions() VeritysetupOptions {
	return VeritysetupOptions{
		Salt:          "0000000000000000000000000000000000000000000000000000000000000000",
		HashAlgorithm: "sha256",
		DataBlockSize: 4096,
		HashBlockSize: 4096,
	}
}

// VerityCalculator provides dm-verity root hash calculation capabilities.
// Decoupled from EROFS conversion - this is purely about dm-verity Merkle tree computation.
type VerityCalculator struct {
	// TempDir for temporary device files
	TempDir string
}

// NewVerityCalculator creates a new dm-verity calculator
func NewVerityCalculator(tempDir string) *VerityCalculator {
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &VerityCalculator{
		TempDir: tempDir,
	}
}

// CalculateRootHash computes the dm-verity root hash for EROFS data.
//
// Input: erofsData - EROFS filesystem image bytes
// Output: dm-verity root hash (hex string, e.g., "bef46122f85025cf...")
//
// Process:
// 1. Write EROFS data to temporary file (veritysetup needs a file/device)
// 2. Allocate space for hash tree after data
// 3. Run veritysetup format to compute Merkle tree and root hash
// 4. Parse output to extract root hash
// 5. Clean up temporary files
//
// This follows the containerd PR #9 pattern for veritysetup integration.
func (v *VerityCalculator) CalculateRootHash(ctx context.Context, erofsData []byte, opts *VeritysetupOptions) (string, error) {
	if opts == nil {
		defaultOpts := DefaultVeritysetupOptions()
		opts = &defaultOpts
	}

	// Create temporary file for EROFS data + hash tree
	// We need extra space for the hash tree (approximately 1% of data size, rounded up)
	dataSize := int64(len(erofsData))
	hashSize := (dataSize / 100) + 8192 // Extra space for hash tree
	totalSize := dataSize + hashSize

	erofsFile, err := os.CreateTemp(v.TempDir, "erofs-verity-*.img")
	if err != nil {
		return "", fmt.Errorf("failed to create temp EROFS file: %w", err)
	}
	erofsPath := erofsFile.Name()
	defer os.Remove(erofsPath)

	// Write EROFS data to file
	if _, err := erofsFile.Write(erofsData); err != nil {
		erofsFile.Close()
		return "", fmt.Errorf("failed to write EROFS data: %w", err)
	}

	// Extend file to accommodate hash tree
	if err := erofsFile.Truncate(totalSize); err != nil {
		erofsFile.Close()
		return "", fmt.Errorf("failed to extend file for hash tree: %w", err)
	}
	erofsFile.Close()

	fmt.Printf("[veritysetup] Computing dm-verity root hash for %d byte EROFS image...\n", len(erofsData))
	fmt.Printf("[veritysetup] Allocated %d bytes total (data: %d, hash: %d)\n", totalSize, dataSize, hashSize)

	// Set hash offset to start after data
	opts.HashOffset = uint64(dataSize)

	// Calculate number of data blocks
	blockSize := uint64(opts.DataBlockSize)
	if blockSize == 0 {
		blockSize = 4096
	}
	opts.DataBlocks = uint64(dataSize) / blockSize
	if uint64(dataSize)%blockSize != 0 {
		opts.DataBlocks++
	}

	// Run veritysetup format to calculate root hash
	rootHash, err := v.runVeritysetupFormat(ctx, erofsPath, erofsPath, opts)
	if err != nil {
		return "", fmt.Errorf("veritysetup format failed: %w", err)
	}

	fmt.Printf("[veritysetup] ✓ Calculated root hash: %s\n", rootHash)
	return rootHash, nil
} // runVeritysetupFormat executes veritysetup format and extracts the root hash
// Following containerd PR #9 implementation pattern
func (v *VerityCalculator) runVeritysetupFormat(ctx context.Context, dataDevice, hashDevice string, opts *VeritysetupOptions) (string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, veritysetupTimeout)
	defer cancel()

	// Build veritysetup command with options
	args := []string{"format"}

	if opts.Salt != "" {
		args = append(args, fmt.Sprintf("--salt=%s", opts.Salt))
	}
	if opts.HashAlgorithm != "" {
		args = append(args, fmt.Sprintf("--hash=%s", opts.HashAlgorithm))
	}
	if opts.DataBlockSize > 0 {
		args = append(args, fmt.Sprintf("--data-block-size=%d", opts.DataBlockSize))
	}
	if opts.HashBlockSize > 0 {
		args = append(args, fmt.Sprintf("--hash-block-size=%d", opts.HashBlockSize))
	}
	if opts.DataBlocks > 0 {
		args = append(args, fmt.Sprintf("--data-blocks=%d", opts.DataBlocks))
	}
	if opts.HashOffset > 0 {
		args = append(args, fmt.Sprintf("--hash-offset=%d", opts.HashOffset))
	}

	args = append(args, dataDevice, hashDevice)

	cmd := exec.CommandContext(cmdCtx, "veritysetup", args...)

	// Force C locale to ensure consistent output parsing (containerd PR #9 pattern)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Printf("[veritysetup] Running: veritysetup %s\n", strings.Join(args, " "))

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("veritysetup command failed: %w, stdout: %s, stderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Extract root hash from output (containerd PR #9 pattern)
	rootHash, err := extractRootHashFromOutput(stdout.String())
	if err != nil {
		return "", fmt.Errorf("failed to extract root hash: %w, output: %s", err, stdout.String())
	}

	return rootHash, nil
}

// extractRootHashFromOutput parses veritysetup format output to extract root hash
// Following containerd PR #9 ExtractRootHash implementation
func extractRootHashFromOutput(output string) (string, error) {
	if output == "" {
		return "", fmt.Errorf("output is empty")
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		// Look for the "Root hash:" line
		if strings.HasPrefix(line, "Root hash:") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				rootHash := strings.TrimSpace(parts[1])
				if rootHash == "" {
					return "", fmt.Errorf("root hash is empty")
				}
				return rootHash, nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error scanning output: %w", err)
	}

	return "", fmt.Errorf("root hash not found in veritysetup output")
}

// IsVeritysetupSupported checks if veritysetup is available and functional
func IsVeritysetupSupported() (bool, error) {
	// Check if veritysetup is in PATH
	if _, err := exec.LookPath("veritysetup"); err != nil {
		return false, fmt.Errorf("veritysetup not found (install cryptsetup package): %w", err)
	}

	// Check if dm_verity kernel module is loaded
	moduleData, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false, fmt.Errorf("failed to read /proc/modules: %w", err)
	}
	if !bytes.Contains(moduleData, []byte("dm_verity")) {
		return false, fmt.Errorf("dm_verity kernel module not loaded (run: modprobe dm_verity)")
	}

	// Verify veritysetup is functional
	cmd := exec.Command("veritysetup", "--version")
	if _, err := cmd.CombinedOutput(); err != nil {
		return false, fmt.Errorf("veritysetup not functional: %w", err)
	}

	return true, nil
}
