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
	// veritysetupTimeout is the maximum time allowed for a single veritysetup invocation.
	veritysetupTimeout = 5 * time.Minute
	// defaultSalt is an all-zero 64 hex char salt for deterministic builds.
	defaultSalt = "0000000000000000000000000000000000000000000000000000000000000000"
	// defaultHashAlgorithm is the dm-verity hash algorithm.
	defaultHashAlgorithm = "sha256"
	// defaultBlockSize is the data & hash block size.
	// erofs-snapshotter uses 512 for both data and hash blocks (VERITY_BLOCK_SIZE constant).
	defaultBlockSize = 512
)

// VeritysetupOptions contains configuration for dm-verity operations
type VeritysetupOptions struct {
	Salt          string // Hex salt. All-zero keeps output deterministic.
	HashAlgorithm string // Hash algorithm (sha256)
	DataBlockSize uint32 // Data block size in bytes
	HashBlockSize uint32 // Hash block size in bytes
	DataBlocks    uint64 // Calculated if zero
	HashOffset    uint64 // Set to data size (start of Merkle tree)
}

// DefaultVeritysetupOptions returns default dm-verity options for containerd compatibility
func DefaultVeritysetupOptions() VeritysetupOptions {
	return VeritysetupOptions{
		Salt:          defaultSalt,
		HashAlgorithm: defaultHashAlgorithm,
		DataBlockSize: defaultBlockSize,
		HashBlockSize: defaultBlockSize,
	}
}

// VerityCalculator provides dm-verity root hash calculation capabilities decoupled from EROFS conversion
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
// Output: dm-verity root hash
//
// Process:
// 1. Write EROFS data to temporary file (veritysetup needs a file/device)
// 2. Allocate space for hash tree after data
// 3. Run veritysetup format to compute Merkle tree and root hash
// 4. Parse output to extract root hash
// 5. Clean up temporary files
func (v *VerityCalculator) CalculateRootHash(ctx context.Context, erofsData []byte, opts *VeritysetupOptions) (string, error) {
	if len(erofsData) == 0 {
		return "", fmt.Errorf("EROFS data is empty")
	}

	if opts == nil {
		defaultOpts := DefaultVeritysetupOptions()
		opts = &defaultOpts
	}

	// Early availability check for clearer error.
	if _, err := exec.LookPath("veritysetup"); err != nil {
		return "", fmt.Errorf("veritysetup not found in PATH: install 'cryptsetup' package (apt install cryptsetup / dnf install cryptsetup): %w", err)
	}

	// Prepare data file (EROFS image)
	dataSize := int64(len(erofsData))
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

	erofsFile.Close()

	// Set HashOffset to dataSize to match this behavior.
	if opts.HashOffset == 0 {
		opts.HashOffset = uint64(dataSize)
	}

	// If appending to the same file, expand the data file to accommodate tree
	var hashDevicePath string
	if opts.HashOffset > 0 {
		// Append mode: expand data file to hold tree
		hashSize := (dataSize / 100) + 8192
		totalSize := dataSize + hashSize
		f, err := os.OpenFile(erofsPath, os.O_WRONLY, 0)
		if err != nil {
			return "", fmt.Errorf("failed to open EROFS file for append: %w", err)
		}
		if err := f.Truncate(totalSize); err != nil {
			f.Close()
			return "", fmt.Errorf("failed to extend file for hash tree: %w", err)
		}
		f.Close()
		hashDevicePath = erofsPath
	} else {
		// Separate hash device
		hashFile, err := os.CreateTemp(v.TempDir, "erofs-verity-hash-*.img")
		if err != nil {
			return "", fmt.Errorf("failed to create temp hash file: %w", err)
		}
		hashDevicePath = hashFile.Name()
		hashFile.Close()
		defer os.Remove(hashDevicePath)
	}

	// Calculate number of data blocks (ceiling division for partial tail block).
	blockSize := uint64(opts.DataBlockSize)
	if blockSize == 0 {
		blockSize = defaultBlockSize
	}
	opts.DataBlocks = (uint64(dataSize) + (blockSize - 1)) / blockSize

	// Run veritysetup format to calculate root hash
	rootHash, err := v.runVeritysetupFormat(ctx, erofsPath, hashDevicePath, opts)
	if err != nil {
		return "", fmt.Errorf("veritysetup format failed: %w", err)
	}

	return rootHash, nil
}

// runVeritysetupFormat executes veritysetup format and extracts the root hash
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

	// Force C locale to ensure consistent output parsing
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("veritysetup command failed: %w, stdout: %s, stderr: %s",
			err, stdout.String(), stderr.String())
	}

	// Extract root hash from output
	rootHash, err := extractRootHashFromOutput(stdout.String())
	if err != nil {
		return "", fmt.Errorf("failed to extract root hash: %w, output: %s", err, stdout.String())
	}

	return rootHash, nil
}

// extractRootHashFromOutput parses veritysetup format output to extract root hash
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

	return "", fmt.Errorf("root hash not found in veritysetup output (expected 'Root hash:' line)")
}
