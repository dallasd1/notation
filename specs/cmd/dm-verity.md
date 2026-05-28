# notation sign --dm-verity

## Description

Use `notation sign --dm-verity` to sign OCI image layers with dm-verity root hashes for kernel-level integrity verification.

This feature generates PKCS#7 signatures of dm-verity Merkle tree root hashes for each layer in the image. The signatures are compatible with the Linux kernel's dm-verity subsystem and containerd's tardev-snapshotter, enabling cryptographic verification of container filesystem integrity at the block device level.

When `--dm-verity` is specified, notation performs two types of signing:

1. **Layer signatures (PKCS#7)**: Each layer is converted to EROFS format, a dm-verity root hash is computed, and the root hash is signed using PKCS#7 (RSASSA-PKCS1-v1_5). These signatures are stored as an OCI artifact referencing the image manifest.

2. **Manifest signature (JWS/COSE)**: The image manifest is signed using the standard notation signature format (JWS or COSE as specified by `--signature-format`).

Upon successful signing, output is:

```text
Successfully signed <registry>/<repository>@<digest>
Pushed the signature to <registry>/<repository>@<signature_digest>
```

NOTE: This is an experimental feature. Set `NOTATION_EXPERIMENTAL=1` to enable the `--dm-verity` flag.

## Prerequisites

The following tools must be installed and available in PATH:

| Tool | Package | Purpose |
|------|---------|---------|
| `mkfs.erofs` | `erofs-utils` | Convert tar.gz layers to EROFS filesystem format |
| `veritysetup` | `cryptsetup` | Compute dm-verity Merkle tree root hash |

Install on Debian/Ubuntu:
```bash
sudo apt install erofs-utils cryptsetup
```

Install on Fedora/RHEL:
```bash
sudo dnf install erofs-utils cryptsetup
```

## Outline

```text
Sign artifacts with dm-verity layer signatures

Usage:
  notation sign --dm-verity [flags] <reference>

Flags:
       --dm-verity                   [Experimental] sign image layers with dm-verity for kernel-level integrity verification
       --id string                   key id (required if --plugin is set)
       --plugin string               signing plugin name
       --plugin-config stringArray   {key}={value} pairs passed to the plugin
       --signature-format string     signature envelope format for manifest signature: "jws", "cose" (default "jws")
  -d,  --debug                       debug mode
  -h,  --help                        help for sign
```

### Signature Manifest Format

dm-verity layer signatures are stored as an OCI artifact with:

- **Artifact Type**: `application/vnd.oci.mt.pkcs7`
- **Subject**: Reference to the signed image manifest
- **Layers**: One descriptor per layer containing the PKCS#7 signature

Each layer descriptor includes annotations:

| Annotation | Description |
|------------|-------------|
| `image.layer.digest` | Original layer digest (e.g., `sha256:abc...`) |
| `image.layer.root_hash` | dm-verity root hash (hex string) |
| `image.layer.signature` | Base64-encoded PKCS#7 signature |

Example signature manifest:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.oci.mt.pkcs7",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.erofs.sig",
      "digest": "sha256:...",
      "size": 2013,
      "annotations": {
        "image.layer.digest": "sha256:17eec7bbc9d79fa397ac95c7283ecd04d1fe6978516932a3db110c6206430809",
        "image.layer.root_hash": "94d5c17ad918e91147e71443c5dfe2e2c95cbf27ddd7674213422801a6925d4a",
        "image.layer.signature": "MIIH2QYJKoZIhvcNAQcCoIIHyjCCB8YCAQExDTAL..."
      }
    }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:2771e37a12b7bcb2902456ecf3f29bf9ee11ec348e66e8eb322d9780ad7fc2df",
    "size": 1035
  }
}
```

## Usage

### Sign with dm-verity using a plugin

```bash
# Enable experimental features
export NOTATION_EXPERIMENTAL=1

# Sign with dm-verity using Azure Key Vault plugin
notation sign --dm-verity \
  --plugin azure-kv \
  --id "https://myvault.vault.azure.net/keys/my-signing-key" \
  myregistry.azurecr.io/myimage@sha256:abc123...
```

### Sign with dm-verity using a local key

```bash
export NOTATION_EXPERIMENTAL=1

# Add a local signing key
notation key add --name mykey --plugin-config "" \
  --key /path/to/key.pem --cert /path/to/cert.pem

# Sign with dm-verity
notation sign --dm-verity --key mykey myregistry.azurecr.io/myimage@sha256:abc123...
```

### Sign with dm-verity and COSE manifest signature

```bash
export NOTATION_EXPERIMENTAL=1

notation sign --dm-verity \
  --signature-format cose \
  --plugin azure-kv \
  --id "https://myvault.vault.azure.net/keys/my-signing-key" \
  myregistry.azurecr.io/myimage@sha256:abc123...
```

## Plugin Configuration

When `--dm-verity` is specified, notation automatically injects the following plugin configuration:

```
signing_scheme=rsassa-pkcs1-v1_5
```

This instructs the plugin to use RSASSA-PKCS1-v1_5 (RS256/RS384/RS512) instead of RSASSA-PSS (PS256/PS384/PS512). PKCS#1 v1.5 signatures are required for compatibility with the Linux kernel's dm-verity signature verification.

Plugins that support dm-verity signing should read the `signing_scheme` plugin config and select the appropriate algorithm:

| signing_scheme | RSA Algorithm | Use Case |
|----------------|---------------|----------|
| `rsassa-pss` (default) | PS256/PS384/PS512 | Standard notation signatures |
| `rsassa-pkcs1-v1_5` | RS256/RS384/RS512 | dm-verity PKCS#7 signatures |

### Manual plugin config override

Users can also specify the signing scheme manually:

```bash
notation sign --dm-verity \
  --plugin azure-kv \
  --id "https://myvault.vault.azure.net/keys/my-key" \
  --plugin-config "signing_scheme=rsassa-pkcs1-v1_5" \
  myregistry.azurecr.io/myimage@sha256:abc123...
```

## How It Works

### Signing Process

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. Fetch image manifest from registry                              │
│  2. For each layer:                                                 │
│     a. Download layer blob (tar.gz)                                 │
│     b. Decompress and convert to EROFS filesystem                   │
│     c. Compute dm-verity Merkle tree root hash                      │
│     d. Sign root hash with PKCS#7 (RSASSA-PKCS1-v1_5)              │
│  3. Create signature manifest (OCI artifact)                        │
│  4. Push signature blobs and manifest to registry                   │
│  5. Sign image manifest with JWS/COSE (standard notation flow)      │
└─────────────────────────────────────────────────────────────────────┘
```

### EROFS Conversion

Layers are converted to EROFS using tar-index mode for compatibility with kata-containers:

```bash
# Equivalent mkfs.erofs command
mkfs.erofs --tar=i -T 0 --mkfs-time -U c1b9d5a2-f162-11cf-9ece-0020afc76f16 --aufs --quiet output.erofs input.tar
```

Parameters:
- `--tar=i`: Tar index mode (metadata only, references original tar)
- `-T 0`: Zero unix timestamp for deterministic builds
- `-U`: Fixed UUID for deterministic builds
- `--aufs`: Convert OCI whiteouts to overlayfs metadata

### dm-verity Root Hash

The root hash is computed using veritysetup with kata-compatible parameters:

```bash
# Equivalent veritysetup command
veritysetup format \
  --salt=0000000000000000000000000000000000000000000000000000000000000000 \
  --hash=sha256 \
  --data-block-size=512 \
  --hash-block-size=512 \
  --data-blocks=<N> \
  --hash-offset=<data_size> \
  <erofs_image> <erofs_image>
```

Parameters:
- 512-byte block sizes (matches kata's `VERITY_BLOCK_SIZE`)
- Zero salt for deterministic builds
- SHA256 hash algorithm
- Hash tree appended to same file (inline mode)

## Runtime Verification

At runtime, the container runtime (e.g., containerd with tardev-snapshotter) performs:

1. Pull image and signature manifest from registry
2. For each layer:
   - Convert tar.gz to EROFS (same process as signing)
   - Compute dm-verity root hash
   - Verify PKCS#7 signature against trusted certificates
   - Set up dm-verity block device with verified root hash
3. Mount EROFS via dm-verity for integrity-protected reads
4. Linux kernel IPE (Integrity Policy Enforcement) blocks execution of unverified code

## Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| `mkfs.erofs not found in PATH` | erofs-utils not installed | `apt install erofs-utils` |
| `veritysetup not found in PATH` | cryptsetup not installed | `apt install cryptsetup` |
| `layer data is not valid gzip` | Layer blob is corrupted or not gzip compressed | Verify image integrity |
| `failed to create PKCS#7 signer` | Plugin doesn't support RSASSA-PKCS1-v1_5 | Use a compatible plugin or key |
| `PKCS#7 signer produced empty signature` | Signing operation failed | Check plugin logs and key permissions |

## Related Commands

- [`notation sign`](sign.md) - Standard artifact signing
- [`notation verify`](verify.md) - Verify artifact signatures
- [`notation blob sign`](blob.md) - Sign arbitrary blobs

---

# notation verify --dm-verity

## Description

Use `notation verify --dm-verity` to verify the dm-verity PKCS#7 layer
signatures attached to an OCI image by `notation sign --dm-verity`. The
command pulls the signature referrer for the subject image, then for each
image layer it:

1. Locates the matching PKCS#7 signature in the referrer (via the
   `io.cncf.notary.dmverity.layer-digest` annotation).
2. Recomputes the EROFS dm-verity root hash from the OCI layer blob and
   confirms it matches the `io.cncf.notary.dmverity.layer-roothash`
   annotation. *(Skipped if `--no-recompute` is set; see warning below.)*
3. Confirms the PKCS#7 SignedData payload (the bytes the signer hashed) is
   the same root hash, so an attacker who tampered with the annotation
   alone is caught.
4. Verifies the PKCS#7 envelope matches the dm-verity sign profile (single
   signer, detached, SHA-256, RSA-2048, no signed attributes).
5. Builds an `x509` chain from the leaf in the envelope to a root in the
   user-supplied CA bundle (`--ca`), requiring the leaf to carry the
   `Code Signing` Extended Key Usage.

`notation verify --dm-verity` performs **only** dm-verity layer verification.
The image manifest's standard notation signature (JWS/COSE) is **not**
verified by this command. Run `notation verify` (without `--dm-verity`)
separately if you also want manifest verification.

NOTE: This is an experimental feature. Set `NOTATION_EXPERIMENTAL=1` to
enable the `--dm-verity` flag.

## Outline

```text
notation verify --dm-verity --ca <pem-path> [--no-recompute] <registry>/<repository>@<digest>
```

## Flags

| Flag | Required | Description |
|------|----------|-------------|
| `--dm-verity` | Yes | Run dm-verity layer verification instead of the standard manifest verify. |
| `--ca <path>` | Yes (with `--dm-verity`) | Path to a PEM file containing one or more trusted root CA certificates. At least one `CERTIFICATE` block is required. |
| `--no-recompute` | No | Skip step 2 (root-hash recomputation from the layer blob). See "Modes" below. |

The reference argument must resolve to a single-platform image manifest;
multi-arch image indexes are not supported (pass a per-platform digest
instead).

`--dm-verity` is incompatible with `--oci-layout`, `--scope`,
`--plugin-config`, and `--user-metadata` (none of which apply to
dm-verity layer verification). The command will reject those combinations
explicitly.

## Modes

### Full verification (default)

```bash
notation verify --dm-verity --ca trust-root.pem registry.example.com/app@sha256:...
```

The default mode is kernel-equivalent: it re-derives each layer's
dm-verity root hash from the layer blob and confirms the signed hash
matches. This catches *every* class of tampering — tampered annotations,
tampered signature bodies, and tampered layer content.

### Annotation-only mode (`--no-recompute`)

```bash
notation verify --dm-verity --ca trust-root.pem --no-recompute registry.example.com/app@sha256:...
```

Skips the EROFS recompute and verifies only that the PKCS#7 envelope
chains to a trusted CA. This mode is dramatically faster (it does not
pull layer blobs) but **only proves a trusted signer signed *some* root
hash for each layer**; it does NOT prove the signed root hash belongs to
the OCI layer at that digest. The command prints a warning to that effect
on every invocation.

`--no-recompute` is useful for fast policy spot-checks but must NOT be
the gate for production rollout. For full integrity, omit it.

## Output

```text
Verifying dm-verity layer signatures for registry.example.com/app@sha256:abc...
NOTE: this command verifies dm-verity layer PKCS#7 signatures only.
      The image manifest signature is NOT verified by this command;
      run `notation verify` (without --dm-verity) for that.
dm-verity referrer: sha256:def... (8 signatures)

LAYER                                                                     ROOT HASH                                                         STATUS
sha256:17eec7bbc9d79fa3...                                                94d5c17ad918e911...                                               PASS
sha256:2771e37a12b7bcb2...                                                a1b2c3d4e5f6789a...                                               FAIL (rsa.VerifyPKCS1v15: crypto/rsa: verification error)
...

FAIL: 7/8 dm-verity signatures verified; 1 failed
```

Exit code is `0` only when every layer passes; otherwise it is non-zero.

## Error Messages (verify)

| Error | Cause | Solution |
|-------|-------|----------|
| `--ca is required when --dm-verity is set` | `--ca` not provided | Pass `--ca <pem-path>` |
| `--ca is only valid with --dm-verity` | `--ca` used without `--dm-verity` | Drop `--ca` or add `--dm-verity` |
| `no dm-verity signatures found for <digest>` | Image has no dm-verity referrer | Re-sign with `notation sign --dm-verity` |
| `ambiguous: N dm-verity referrers found` | Subject has multiple dm-verity referrers | Out of scope for v1; remove extras |
| `dm-verity verify requires an image manifest, but ... resolves to ...index...` | Reference is a multi-arch index | Pass a per-platform digest |
| `signature payload (signed hash) does not match annotated layer-roothash` | Annotation was tampered or signature is for a different hash | Investigate referrer; re-sign |
| `computed dm-verity root hash does not match annotated layer-roothash` | Layer blob was tampered after signing | Re-sign or quarantine the image |
| `leaf certificate ... does not chain to provided CA` | Wrong `--ca` PEM, or signer cert outside trust store | Provide the correct CA bundle |
| `leaf certificate ... is missing Code Signing EKU` | Cert lacks the required EKU (`1.3.6.1.5.5.7.3.3`) | Reissue cert with Code Signing EKU |

## Related Commands

- [`notation sign`](sign.md) - Standard artifact signing
- [`notation verify`](verify.md) - Verify artifact signatures
- [`notation blob sign`](blob.md) - Sign arbitrary blobs

## References

- [dm-verity kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html)
- [EROFS filesystem](https://erofs.docs.kernel.org/)
- [OCI Image Spec](https://github.com/opencontainers/image-spec)
- [Notary Project Plugin Extensibility](https://github.com/notaryproject/specifications/blob/main/specs/plugin-extensibility.md)
- [containerd tardev-snapshotter](https://github.com/containerd/containerd)
