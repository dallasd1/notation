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

package dmverity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/notaryproject/notation/v2/internal/erofs"
	gopkcs7 "go.mozilla.org/pkcs7"
)

// Profile constants for the dm-verity PKCS#7 layer signature profile.
// Mirror what notation-core-go/signature/pkcs7 enforces on the sign side.
const (
	profileKeyBits = 2048 // RSA-2048 only
	rootHashHexLen = 64   // SHA-256, lowercase hex
)

// Status is the per-layer verify outcome.
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
)

// LayerVerifyResult is the per-layer verify outcome.
type LayerVerifyResult struct {
	// LayerDigest is the OCI digest of the image layer being verified.
	LayerDigest string
	// AnnotatedHash is the root hash declared in the signature descriptor
	// annotation (`io.cncf.notary.dmverity.layer-roothash`).
	AnnotatedHash string
	// ComputedHash is the root hash recomputed from the layer blob. Empty when
	// LayerVerifier.Recompute is false.
	ComputedHash string
	// LeafSubject is the leaf certificate's Subject DN (for human-readable
	// output). Empty when verification fails before the leaf is identified.
	LeafSubject string
	// Status is StatusPass on success, StatusFail otherwise.
	Status Status
	// Err is the first error encountered during verification, or nil on
	// success.
	Err error
}

// RecomputeFunc recomputes the dm-verity root hash of an OCI layer blob.
// layerDigest is the OCI descriptor digest of the layer (e.g. "sha256:...");
// it MUST be threaded through to the EROFS converter so the superblock UUID
// matches containerd's per-layer derivation.
//
// Used by LayerVerifier; production builds use defaultRecompute (mkfs.erofs +
// veritysetup). Tests inject a fake to avoid the binary dependencies.
type RecomputeFunc func(ctx context.Context, layerDigest string, layerBlob []byte) (string, error)

// LayerVerifier verifies dm-verity PKCS#7 layer signatures against a CA pool.
type LayerVerifier struct {
	// Roots is the trust anchor pool. Leaf certificates from each PKCS#7
	// envelope must chain to one of these roots.
	Roots *x509.CertPool

	// Recompute, when true, regenerates the dm-verity root hash from the
	// layer blob and asserts it matches both the annotation and the signed
	// payload. Required for true integrity (kernel-equivalent semantics);
	// when false, the verifier only proves a trusted signer signed *some*
	// root hash, not that the hash belongs to the layer.
	Recompute bool

	// RequireCodeSignEKU, when true, requires the leaf certificate to carry
	// the Code Signing Extended Key Usage (1.3.6.1.5.5.7.3.3) explicitly.
	// Go's x509.Verify treats a cert with no EKU as valid for any usage; this
	// flag adds an explicit membership check on top.
	RequireCodeSignEKU bool

	// Now is the time at which cert validity is evaluated. Zero means
	// time.Now(). Exposed for testability.
	Now time.Time

	// RecomputeFn overrides the default EROFS+veritysetup pipeline. nil means
	// use defaultRecompute. Tests inject a fake.
	RecomputeFn RecomputeFunc
}

// VerifyLayerSignature performs the full per-layer dm-verity verification.
//
// Steps:
//  1. Validate annotatedRootHash is 64-char lowercase hex.
//  2. Parse the PKCS#7 envelope and enforce the dm-verity profile (1 signer,
//     no signed attrs, detached content, SHA-256 digest, RSA encryption,
//     non-empty cert chain).
//  3. Identify the leaf via SignerInfo's IssuerAndSerialNumber (NOT blindly
//     Certificates[0]).
//  4. Enforce RSA-2048 leaf.
//  5. If Recompute is true, regenerate the root hash from layerBlob and
//     compare to the annotation. The signed payload is then the computed
//     hash; otherwise it is the annotated hash.
//  6. Verify rsa.VerifyPKCS1v15(leafPub, SHA-256, sha256(payloadHash), sig).
//  7. Verify leaf chains to v.Roots using PKCS#7-bundled intermediates, at
//     v.Now (or time.Now()), with KeyUsage = code-signing.
//  8. If RequireCodeSignEKU, explicitly assert Code Signing EKU is in
//     leaf.ExtKeyUsage.
//
// On any failure, Status is StatusFail and Err names the first problem.
//
// layerBlob may be nil iff Recompute is false.
func (v *LayerVerifier) VerifyLayerSignature(
	ctx context.Context,
	layerDigest string,
	layerBlob []byte,
	annotatedRootHash string,
	pkcs7Sig []byte,
) LayerVerifyResult {
	res := LayerVerifyResult{
		LayerDigest:   layerDigest,
		AnnotatedHash: annotatedRootHash,
		Status:        StatusFail,
	}

	if !isLowerHex256(annotatedRootHash) {
		res.Err = fmt.Errorf("layer-roothash annotation %q is not 64-char lowercase hex", annotatedRootHash)
		return res
	}

	if len(pkcs7Sig) == 0 {
		res.Err = errors.New("PKCS#7 signature is empty")
		return res
	}

	p7, err := gopkcs7.Parse(pkcs7Sig)
	if err != nil {
		res.Err = fmt.Errorf("parse PKCS#7: %w", err)
		return res
	}

	if err := enforceDmverityProfile(p7); err != nil {
		res.Err = err
		return res
	}

	leaf, err := findSignerCert(p7)
	if err != nil {
		res.Err = err
		return res
	}
	res.LeafSubject = leaf.Subject.String()

	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		res.Err = fmt.Errorf("leaf public key is %T, want *rsa.PublicKey", leaf.PublicKey)
		return res
	}
	if got := pub.N.BitLen(); got != profileKeyBits {
		res.Err = fmt.Errorf("leaf key size is RSA-%d, want RSA-%d", got, profileKeyBits)
		return res
	}

	payloadHash := annotatedRootHash
	if v.Recompute {
		if layerBlob == nil {
			res.Err = errors.New("recompute requested but layerBlob is nil")
			return res
		}
		fn := v.RecomputeFn
		if fn == nil {
			fn = defaultRecompute
		}
		computed, err := fn(ctx, layerDigest, layerBlob)
		if err != nil {
			res.Err = fmt.Errorf("recompute root hash: %w", err)
			return res
		}
		if !isLowerHex256(computed) {
			res.Err = fmt.Errorf("recomputed root hash %q is not 64-char lowercase hex", computed)
			return res
		}
		res.ComputedHash = computed
		if !strings.EqualFold(computed, annotatedRootHash) {
			res.Err = fmt.Errorf("recomputed root hash %s does not match annotation %s", computed, annotatedRootHash)
			return res
		}
		payloadHash = computed
	}

	si := p7.Signers[0]
	digest := sha256.Sum256([]byte(payloadHash))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], si.EncryptedDigest); err != nil {
		res.Err = fmt.Errorf("rsa.VerifyPKCS1v15: %w", err)
		return res
	}

	if v.Roots == nil {
		res.Err = errors.New("no CA roots configured for chain verification")
		return res
	}
	intermediates := x509.NewCertPool()
	for _, c := range p7.Certificates {
		if c.Equal(leaf) {
			continue
		}
		intermediates.AddCert(c)
	}
	now := v.Now
	if now.IsZero() {
		now = time.Now()
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		res.Err = fmt.Errorf("x509 chain verify: %w", err)
		return res
	}

	if v.RequireCodeSignEKU && !hasCodeSigningEKU(leaf) {
		res.Err = fmt.Errorf("leaf certificate %q does not carry Code Signing EKU (1.3.6.1.5.5.7.3.3)", leaf.Subject)
		return res
	}

	res.Status = StatusPass
	res.Err = nil
	return res
}

// enforceDmverityProfile re-checks the dm-verity PKCS#7 profile on a parsed
// envelope. notation-core-go's pkcs7.ParseEnvelope only enforces "exactly 1
// signer + non-empty signature"; the rest of the profile (no signed attrs,
// detached, SHA-256, RSA, non-empty certs) is asserted here so the verifier
// matches what the sign side actually produces.
func enforceDmverityProfile(p7 *gopkcs7.PKCS7) error {
	if len(p7.Signers) != 1 {
		return fmt.Errorf("dm-verity PKCS#7 envelope requires exactly 1 signer, got %d", len(p7.Signers))
	}
	si := p7.Signers[0]
	if len(si.EncryptedDigest) == 0 {
		return errors.New("dm-verity PKCS#7 envelope has empty signature")
	}
	if len(si.AuthenticatedAttributes) != 0 {
		return fmt.Errorf("dm-verity PKCS#7 envelope must not have signed attributes (got %d)", len(si.AuthenticatedAttributes))
	}
	if len(p7.Content) != 0 {
		return fmt.Errorf("dm-verity PKCS#7 envelope must be detached (got %d bytes of content)", len(p7.Content))
	}
	if !si.DigestAlgorithm.Algorithm.Equal(gopkcs7.OIDDigestAlgorithmSHA256) {
		return fmt.Errorf("dm-verity PKCS#7 envelope digest algorithm is %v, want SHA-256", si.DigestAlgorithm.Algorithm)
	}
	if !si.DigestEncryptionAlgorithm.Algorithm.Equal(gopkcs7.OIDEncryptionAlgorithmRSA) {
		return fmt.Errorf("dm-verity PKCS#7 envelope encryption algorithm is %v, want RSA (PKCS#1 v1.5)", si.DigestEncryptionAlgorithm.Algorithm)
	}
	if len(p7.Certificates) == 0 {
		return errors.New("dm-verity PKCS#7 envelope has no certificates")
	}
	return nil
}

// findSignerCert resolves the leaf cert by matching SignerInfo's
// IssuerAndSerialNumber against the certs in the SignedData. This is the
// correct CMS-level identification: blindly trusting p7.Certificates[0] would
// accept malformed envelopes the kernel could later reject.
func findSignerCert(p7 *gopkcs7.PKCS7) (*x509.Certificate, error) {
	si := p7.Signers[0]
	wantSerial := si.IssuerAndSerialNumber.SerialNumber
	wantIssuer := si.IssuerAndSerialNumber.IssuerName.FullBytes
	for _, c := range p7.Certificates {
		if c.SerialNumber == nil || wantSerial == nil {
			continue
		}
		if c.SerialNumber.Cmp(wantSerial) != 0 {
			continue
		}
		if bytes.Equal(c.RawIssuer, wantIssuer) {
			return c, nil
		}
	}
	return nil, errors.New("no certificate in CMS matches SignerInfo IssuerAndSerialNumber")
}

// hasCodeSigningEKU returns true iff the certificate's ExtKeyUsage slice
// includes Code Signing.
func hasCodeSigningEKU(c *x509.Certificate) bool {
	for _, eku := range c.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

// isLowerHex256 returns true iff s is 64 lowercase hex characters.
func isLowerHex256(s string) bool {
	if len(s) != rootHashHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// defaultRecompute regenerates the dm-verity root hash for layerBlob using
// the same EROFS+veritysetup pipeline the sign side uses. The leading
// layerDigest is required so the EROFS superblock UUID matches containerd's
// per-layer derivation.
func defaultRecompute(ctx context.Context, layerDigest string, layerBlob []byte) (string, error) {
	converter := erofs.NewConverter("")
	erofsData, err := converter.ConvertLayerToEROFS(ctx, layerDigest, layerBlob)
	if err != nil {
		return "", fmt.Errorf("EROFS conversion failed: %w", err)
	}
	calc := erofs.NewVerityCalculator("")
	opts := erofs.DefaultVeritysetupOptions()
	rootHash, err := calc.CalculateRootHash(ctx, erofsData, &opts)
	if err != nil {
		return "", fmt.Errorf("dm-verity root hash calculation failed: %w", err)
	}
	return rootHash, nil
}

// LoadCAPool reads pemPath and returns an x509.CertPool containing every
// CERTIFICATE block in the file. Returns an error if the file contains zero
// CERTIFICATE blocks or any block fails to parse.
func LoadCAPool(pemPath string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, fmt.Errorf("read CA file %s: %w", pemPath, err)
	}
	pool := x509.NewCertPool()
	rest := raw
	loaded := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate #%d in %s: %w", loaded, pemPath, err)
		}
		pool.AddCert(c)
		loaded++
	}
	if loaded == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in %s", pemPath)
	}
	return pool, nil
}
