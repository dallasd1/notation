# EROFS Package

Modular utilities for EROFS filesystem conversion and dm-verity root hash calculation.

## Overview

This package provides **decoupled**, **reusable** utilities for:
1. **EROFS Conversion**: Converting OCI layer tarballs (tar.gz) to EROFS filesystem format
2. **dm-verity Root Hash Calculation**: Computing Merkle tree root hashes for integrity verification

## Design Philosophy

Following the same modular architecture as `internal/registryutil`:
- **Decoupled from commands**: Not tied to sign, verify, or any specific command
- **General-purpose**: Can be reused anywhere EROFS/dm-verity operations are needed
- **Clean interfaces**: Simple, focused APIs with clear responsibilities
- **External tool integration**: Shells out to `mkfs.erofs` and `veritysetup` CLI tools

## Components

### 1. EROFS Converter (`converter.go`)

Converts compressed OCI layer tarballs to EROFS filesystem images.

```go
converter := erofs.NewConverter("")
erofsData, err := converter.ConvertLayerToEROFS(ctx, layerData)
```

**Process:**
1. Decompress gzip to extract tar
2. Extract tar contents to temporary directory  
3. Run `mkfs.erofs` to create EROFS filesystem
4. Return EROFS image as bytes
5. Clean up temporary files

### 2. Veritysetup Calculator (`veritysetup.go`)

Computes dm-verity root hashes using the `veritysetup` CLI tool.

```go
calculator := erofs.NewVerityCalculator("")
opts := erofs.DefaultVeritysetupOptions()
rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
```

**Process:**
1. Write EROFS data to temporary file
2. Run `veritysetup format` to compute Merkle tree
3. Parse output to extract root hash
4. Clean up temporary files

Based on [containerd PR #9](https://github.com/aadhar-agarwal/containerd/pull/9) implementation pattern.

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

```go
// Check if EROFS tools are available
erofsOK, err := erofs.IsSupported()

// Check if veritysetup and dm_verity module are available
verityOK, err := erofs.IsVeritysetupSupported()
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
    
    // Step 1: Convert OCI layer to EROFS
    converter := erofs.NewConverter("")
    erofsData, err := converter.ConvertLayerToEROFS(ctx, layerData)
    if err != nil {
        return "", err
    }
    
    // Step 2: Calculate dm-verity root hash
    calculator := erofs.NewVerityCalculator("")
    opts := erofs.DefaultVeritysetupOptions()
    rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
    if err != nil {
        return "", err
    }
    
    // Step 3: Sign the root hash with your signer
    // signature := sign(rootHash)
    
    return rootHash, nil
}
```

## Integration with dmverity Package

The `internal/dmverity` package uses these utilities:

```go
// internal/dmverity/dmverity.go
func generateDmVerityRootHash(layerData []byte) (string, error) {
    // Use modular EROFS converter
    converter := erofs.NewConverter("")
    erofsData, err := converter.ConvertLayerToEROFS(ctx, layerData)
    
    // Use modular veritysetup calculator
    calculator := erofs.NewVerityCalculator("")
    rootHash, err := calculator.CalculateRootHash(ctx, erofsData, &opts)
    
    return rootHash, nil
}
```

## Configuration Options

### VeritysetupOptions

```go
type VeritysetupOptions struct {
    Salt          string  // Hex string (default: "0000...0000")
    HashAlgorithm string  // Algorithm (default: "sha256")
    DataBlockSize uint32  // Block size (default: 4096)
    HashBlockSize uint32  // Hash block size (default: 4096)
}
```

### Temporary Directory

Both converters accept a custom temp directory:

```go
converter := erofs.NewConverter("/custom/tmp/path")
calculator := erofs.NewVerityCalculator("/custom/tmp/path")
```

## Testing

Check system requirements:
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

## Architecture Benefits

This modular design enables:
- ✅ **Reusability**: Any component can use EROFS/dm-verity utilities
- ✅ **Testability**: Each utility can be tested independently
- ✅ **Maintainability**: Clear separation of concerns
- ✅ **Flexibility**: Easy to swap implementations or add features
- ✅ **Consistency**: Same pattern as `registryutil.BlobFetcher`
