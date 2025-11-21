# EROFS Package

Modular utilities for EROFS filesystem conversion and dm-verity root hash calculation.

## Overview

This package provides **decoupled**, **reusable** utilities for:
1. **EROFS Conversion**: Converting OCI layer tarballs (tar.gz) to EROFS filesystem format
2. **dm-verity Root Hash Calculation**: Computing Merkle tree root hashes for integrity verification

## What Gets Hashed?

**Critical Understanding**: The dm-verity root hash is calculated on the **EROFS image**, NOT the original tar.gz layer.

### The Complete Process

```
1. OCI Layer (tar.gz)          → 317,652 bytes (compressed)
   ↓ decompress
2. TAR Archive                 → 745,984 bytes (uncompressed)
   ↓ mkfs.erofs --tar=i
3. EROFS Image                 → 747,520 bytes (EROFS metadata + tar)
   ├─ EROFS metadata: 1,536 bytes (filesystem structure)
   ├─ TAR data: 745,984 bytes (original tar appended)
   └─ Padding: aligned to 512-byte boundary
   ↓ veritysetup format
4. dm-verity Root Hash         → a181ece8b70d621f23cddb2d17624048... (64 hex chars)
   ↓ openssl smime -sign
5. PKCS#7 Signature            → 1,206 bytes (DER format)
```

**Key Point**: The root hash is computed on the **747,520-byte EROFS image**, which contains both EROFS metadata and the original tar data. This is NOT the same as hashing the tar.gz or tar directly.

### Why EROFS?

- **dm-verity is block-level**: It requires a filesystem image, not a tar archive
- **Containerd compatibility**: Containerd converts layers to EROFS at runtime
- **Deterministic conversion**: Same tar always produces same EROFS image (using fixed timestamps/UUIDs)
- **Verification at runtime**: Containerd repeats the same conversion and compares root hashes

### Example from Real Signing

```bash
$ notation sign --dm-verity --signature-format pkcs7 akscontainerhost.azurecr.io/test-app:v1

[dmverity.SignImageLayers]  Retrieved 317652 bytes of layer data
[dmverity.generateDmVerityRootHash]  Step 1: Converting tar.gz to EROFS...
[erofs.Converter] Decompressed to 745984 bytes of tar data
[erofs.Converter] Appending 745984 bytes of tar to 1536 bytes of EROFS metadata
[erofs.Converter] Successfully created EROFS image: 747520 bytes
[dmverity.generateDmVerityRootHash]  Step 2: Computing dm-verity Merkle tree root hash...
[veritysetup]  Calculated root hash: a181ece8b70d621f23cddb2d17624048761a1812dc093b23dc954423040cbed8
```

## Design Philosophy

Following the same modular architecture as `internal/registryutil`:
- **Decoupled from commands**: Not tied to sign, verify, or any specific command
- **General-purpose**: Can be reused anywhere EROFS/dm-verity operations are needed
- **Clean interfaces**: Simple, focused APIs with clear responsibilities
- **External tool integration**: Shells out to `mkfs.erofs` and `veritysetup` CLI tools

## Components

### 1. EROFS Converter (`converter.go`)

Converts compressed OCI layer tarballs to EROFS filesystem images.

**Code Path**: `internal/erofs/converter.go`

```go
converter := erofs.NewConverter("")
erofsData, err := converter.ConvertLayerToEROFS(ctx, layerData)
```

**Process:**
1. Decompress gzip to extract tar (`decompressGzip()`)
2. Write tar to temporary file
3. Run `mkfs.erofs --tar=i` to create EROFS metadata (tar index mode)
4. Read EROFS metadata
5. Append original tar data to EROFS metadata
6. Pad to 512-byte alignment
7. Return combined EROFS image as bytes
8. Clean up temporary files

**Key Options for Deterministic Builds:**
- `-T0`: Fixed timestamp (epoch 0)
- `-U c1b9d5a2-f162-11cf-9ece-0020afc76f16`: Fixed UUID
- `--mkfs-time`: Use consistent metadata time
- `--aufs`: Advanced Unix FS mode
- `--tar=i`: TAR index mode (metadata only, tar appended separately)

### 2. Veritysetup Calculator (`veritysetup.go`)

Computes dm-verity root hashes using the `veritysetup` CLI tool.

**Code Path**: `internal/erofs/veritysetup.go`

```go
calculator := erofs.NewVerityCalculator("")
opts := erofs.DefaultVeritysetupOptions()
rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
```

**Process:**
1. Write EROFS data to temporary file
2. Extend file to accommodate hash tree (data + ~1% for hashes)
3. Run `veritysetup format` with 512-byte blocks
4. Parse output to extract root hash (64 hex characters)
5. Clean up temporary files

**Critical Settings (for containerd compatibility):**
- `--data-block-size=512`: 512-byte blocks (NOT 4096)
- `--hash-block-size=512`: 512-byte hash blocks
- `--salt=0000...0000`: Zero salt (64 zeros)
- `--hash=sha256`: SHA-256 algorithm

Based on [containerd PR #9](https://github.com/aadhar-agarwal/containerd/pull/9) implementation pattern.

## Code Flow

### Full Call Chain

```
cmd/notation/sign.go
  └─> runSign() [dm-verity mode]
      └─> dmverity.SignImageLayers()
          └─> generateDmVerityRootHash()
              ├─> erofs.Converter.ConvertLayerToEROFS()
              │   ├─> decompressGzip()
              │   └─> createEROFSMetadataWithTar()
              │       └─> exec: mkfs.erofs --tar=i
              └─> erofs.VerityCalculator.CalculateRootHash()
                  └─> runVeritysetupFormat()
                      └─> exec: veritysetup format --data-block-size=512
```

### File Locations

- **EROFS Conversion**: `internal/erofs/converter.go`
- **dm-verity Calculation**: `internal/erofs/veritysetup.go`
- **Signing Orchestration**: `internal/dmverity/dmverity.go`
- **CLI Integration**: `cmd/notation/sign.go`

## System Requirements

### Required Tools

1. **mkfs.erofs** (EROFS utilities)
   ```bash
   # Ubuntu/Debian
   sudo apt-get install erofs-utils
   
   # Fedora/RHEL
   sudo dnf install erofs-utils
   ```

2. **veritysetup** (Cryptsetup with dm-verity support)
   ```bash
   # Ubuntu/Debian
   sudo apt-get install cryptsetup
   
   # Fedora/RHEL
   sudo dnf install cryptsetup
   ```

3. **dm_verity kernel module**
   ```bash
   sudo modprobe dm_verity
   ```

### Verification

```bash
# Check if tools are available
which mkfs.erofs
which veritysetup

# Check kernel module
lsmod | grep dm_verity

# Test with notation
notation sign --dm-verity --signature-format pkcs7 akscontainerhost.azurecr.io/test-app:v1
```

## Usage Example

Complete workflow for dm-verity signing:

```go
import (
    "context"
    "github.com/notaryproject/notation/v2/internal/erofs"
)

func signLayer(layerData []byte) (string, error) {
    ctx := context.Background()
    
    // Step 1: Convert OCI layer (tar.gz) to EROFS
    converter := erofs.NewConverter("")
    erofsData, err := converter.ConvertLayerToEROFS(ctx, layerData)
    if err != nil {
        return "", err
    }
    // erofsData now contains: EROFS metadata + tar + padding
    
    // Step 2: Calculate dm-verity root hash on EROFS image
    calculator := erofs.NewVerityCalculator("")
    opts := erofs.DefaultVeritysetupOptions()
    rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
    if err != nil {
        return "", err
    }
    // rootHash is computed on the EROFS image, not the tar.gz
    
    // Step 3: Sign the root hash with PKCS#7
    // signature := signWithPKCS7(rootHash)
    
    return rootHash, nil
}
```

## Integration with dmverity Package

The `internal/dmverity` package uses these utilities:

**Code Path**: `internal/dmverity/dmverity.go`

```go
// generateDmVerityRootHash in internal/dmverity/dmverity.go
func generateDmVerityRootHash(layerData []byte) (string, error) {
    // Use modular EROFS converter
    converter := erofs.NewConverter("")
    erofsData, err := converter.ConvertLayerToEROFS(ctx, layerData)
    
    // Use modular veritysetup calculator
    calculator := erofs.NewVerityCalculator("")
    opts := erofs.DefaultVeritysetupOptions()
    rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
    
    return rootHash, nil
}
```

## Configuration Options

### VeritysetupOptions

```go
type VeritysetupOptions struct {
    Salt          string  // Hex string (default: 64 zeros)
    HashAlgorithm string  // Algorithm (default: "sha256")
    DataBlockSize uint32  // Block size (default: 512 for containerd)
    HashBlockSize uint32  // Hash block size (default: 512)
    HashOffset    uint64  // Offset for hash tree
    DataBlocks    uint64  // Number of data blocks
}
```

### Default Options

```go
opts := erofs.DefaultVeritysetupOptions()
// Returns:
// - DataBlockSize: 512 (containerd compatibility)
// - HashBlockSize: 512
// - Salt: "0000...0000" (64 zeros)
// - HashAlgorithm: "sha256"
```

### Temporary Directory

Both converters accept a custom temp directory:

```go
converter := erofs.NewConverter("/custom/tmp/path")
calculator := erofs.NewVerityCalculator("/custom/tmp/path")
```

## Testing

### Quick Test

```bash
# Sign a test image
notation sign --dm-verity --signature-format pkcs7 akscontainerhost.azurecr.io/test-app:v1

# Verify you get consistent root hash
# a181ece8b70d621f23cddb2d17624048761a1812dc093b23dc954423040cbed8
```

### System Requirements Check

```bash
# Verify tools are installed
which mkfs.erofs
which veritysetup

# Check kernel module
lsmod | grep dm_verity

# Load module if needed
sudo modprobe dm_verity
```

## Future Enhancements

Potential optimizations:
- Streaming conversion for large layers (avoid loading full layer into memory)
- In-memory EROFS generation (avoid temp file writes)
- Pure Go implementation of dm-verity Merkle tree (avoid veritysetup dependency)
- EROFS compression options support
- Parallel layer processing
- Deterministic content-derived filesystem UUID instead of fixed constant `c1b9d5a2-f162-11cf-9ece-0020afc76f16` (TODO):
    - Motivation: Preserve reproducibility while restoring per-filesystem uniqueness for observability/debugging; avoid a global UUID across all layers.
    - Approach: Derive UUID from dm-verity root hash (preferred) or SHA-256 of the EROFS image/tar. Use first 16 bytes, set RFC4122 version + variant bits (e.g. treat as v5 style though using SHA-256).
    - Example (conceptual): `uuidBytes := sha256(eroFSImage)[:16]` → set version nibble (0x5) and variant bits → format.
    - Benefits: Same content → same UUID (deterministic); different content → distinct UUID; ties identity to integrity primitive.
    - Migration Plan: Introduce behind flag/env (`--erofs-uuid=derived`), warn when using legacy constant, then promote to default before widespread publishing to avoid breaking existing signatures.
    - Caution: Changing UUID alters EROFS metadata → changes dm-verity root hash → invalidates prior signatures; perform switch only before artifacts are considered immutable.

## Architecture Benefits

This modular design enables:
- ✅ **Reusability**: Any component can use EROFS/dm-verity utilities
- ✅ **Testability**: Each utility can be tested independently
- ✅ **Maintainability**: Clear separation of concerns
- ✅ **Flexibility**: Easy to swap implementations or add features
- ✅ **Consistency**: Same pattern as `registryutil.BlobFetcher`
- ✅ **Transparency**: Clear understanding of what gets hashed (EROFS image, not tar.gz)
