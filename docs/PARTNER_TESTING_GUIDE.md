# DM-Verity Testing Guide for Partners

Quick-start guide for testing dm-verity image signing with notation + containerd.

## 1. Build

### Option A: Container Image (Recommended)

Pull the pre-built setup container so the
tools are installed directly onto the **build machine**:

```bash
docker pull akscontainerhost.azurecr.io/notary-setup:latest
docker run --rm -v /:/host akscontainerhost.azurecr.io/notary-setup:latest
```

This installs:
- `/opt/notation/notation` — notation CLI binary
- `~/.config/notation/plugins/azure-kv/` — Azure Key Vault plugin + shell wrapper
- A test signing key (`partner-key`) for local experimentation

Add notation to your PATH:

```bash
export PATH="/opt/notation:$PATH"
```

Skip to [Section 2: Certificates](#2-certificates) if using this path.

### Option B: Build from Source

Install build dependencies:

```bash
# Go 1.24+, .NET 8.0, erofs-utils, cryptsetup
sudo apt install -y erofs-utils cryptsetup
sudo snap install dotnet-sdk --classic --channel=8.0
```

Clone and build all components. The `dm-verity-dev` branch contains `replace`
directives in `go.mod` that point to sibling directories, so all three Go
repositories must live under the same parent folder:

```bash
mkdir -p ~/notary-project && cd ~/notary-project

# notation-core-go (PKCS#7 envelope branch)
git clone https://github.com/dallasd1/notation-core-go.git -b dadelan/pkcs7-envelope

# notation-go (export signer branch)
git clone https://github.com/dallasd1/notation-go.git -b dadelan/export-plugin-primitive-signer

# notation CLI (dm-verity dev branch — has replace directives for the above)
git clone https://github.com/dallasd1/notation.git -b dadelan/dm-verity-dev
cd notation
go build -o ./bin/notation ./cmd/notation
sudo cp ./bin/notation /usr/local/bin/notation

# notation-azure-kv plugin (PKCS#1 v1.5 branch)
cd ~/notary-project
git clone https://github.com/dallasd1/notation-azure-kv.git -b dadelan/pkcs1-signing-scheme
cd notation-azure-kv
dotnet publish Notation.Plugin.AzureKeyVault/Notation.Plugin.AzureKeyVault.csproj \
  -c Release -o ~/.config/notation/plugins/azure-kv --no-self-contained

# Create a shell wrapper for the plugin.
# The .NET plugin publishes as a DLL, not a standalone executable,
# so this wrapper invokes it via the dotnet runtime.
cat > ~/.config/notation/plugins/azure-kv/notation-azure-kv << 'WRAPPER'
#!/bin/bash
exec dotnet ~/.config/notation/plugins/azure-kv/notation-azure-kv.dll "$@"
WRAPPER
chmod +x ~/.config/notation/plugins/azure-kv/notation-azure-kv
```

Verify:

```bash
notation version
notation plugin list   # should show azure-kv
```

---

## 2. Certificates

### What You Need

| Item | Where | Purpose |
|------|-------|---------|
| RSA key pair | Azure Key Vault | Signs dm-verity root hashes (PKCS#1 v1.5) |
| Leaf certificate | AKV (attached to key) | Included in PKCS#7 envelope, verified by kernel |
| CA / root certificate | UEFI Secure Boot db | Kernel uses this to verify the leaf cert in the PKCS#7 signature |

### Create a Key in Azure Key Vault

```bash
# Create a self-signed cert + key in AKV (RSA 2048)
az keyvault certificate create \
  --vault-name <YOUR_VAULT> \
  --name <YOUR_KEY_NAME> \
  --policy "$(cat <<EOF
{
  "issuerParameters": { "name": "Self" },
  "keyProperties": { "keyType": "RSA", "keySize": 2048, "exportable": false },
  "x509CertificateProperties": {
    "subject": "CN=dm-verity-signer",
    "validityInMonths": 12,
    "keyUsage": ["digitalSignature"]
  }
}
EOF
)"
```

### Download the Public Certificate

```bash
# Download the signing certificate (PEM)
az keyvault certificate download \
  --vault-name <YOUR_VAULT> \
  --name <YOUR_KEY_NAME> \
  --file signer.pem --encoding PEM
```

### Enroll Certificate in UEFI Secure Boot db (container host VM)

The enrollment method depends on how your VM images are built. OS guard uses a Bicep `additionalSignatures.db` entry in the image definition.

---

## 3. Sign an Image

```bash
# Login to your registry
az acr login --name <YOUR_REGISTRY>

# Enable experimental features
export NOTATION_EXPERIMENTAL=1

# Sign with dm-verity (uses AKV key, auto-selects PKCS#1 v1.5)
notation sign --dm-verity \
  --plugin azure-kv \
  --id "https://<YOUR_VAULT>.vault.azure.net/keys/<YOUR_KEY_NAME>" \
  <YOUR_REGISTRY>.azurecr.io/<IMAGE>@<DIGEST>
```

This pushes two artifacts to the registry:
1. **DM-verity referrer** — OCI manifest with PKCS#7 layer signatures and root hashes
2. **Notation signature** — standard JWS/COSE manifest signature

---

## 4. Deploy Containerd with Signature Support (container host VM)

The containerd fork adds EROFS snapshotter + dm-verity signature verification.

### Build Containerd

```bash
cd ~/source
git clone https://github.com/aadhar-agarwal/containerd.git -b aadagarwal/add-signature-support
cd containerd
make
sudo make install
```

### Configure Containerd

Add the EROFS snapshotter with signature verification to `/etc/containerd/config.toml`:

```toml
version = 3

[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "erofs"

[plugins."io.containerd.snapshotter.v1.erofs"]
  enable_signature_verification = true
```

Restart containerd:

```bash
sudo systemctl restart containerd
```

### Verify

Pull a signed image, run it, and confirm dm-verity verification passes:

```bash
sudo ctr image pull <YOUR_REGISTRY>.azurecr.io/<IMAGE>@<DIGEST>
sudo ctr run --rm <YOUR_REGISTRY>.azurecr.io/<IMAGE>@<DIGEST> test-container
```

Check logs for dm-verity verification output:

```bash
sudo journalctl -u containerd --since "5 min ago" | grep -i verity
```

---
