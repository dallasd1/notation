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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	corepkcs7 "github.com/notaryproject/notation-core-go/signature/pkcs7"
	gopkcs7 "go.mozilla.org/pkcs7"
)

const sampleRootHash = "94d5c17ad918e91147e71443c5dfe2e2c95cbf27ddd7674213422801a6925d4a"

func TestVerifyLayerSignature_HappyPath_Recompute(t *testing.T) {
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)

	v := &LayerVerifier{
		Roots:              poolOf(root),
		Recompute:          true,
		RequireCodeSignEKU: true,
		RecomputeFn:        constantHash(sampleRootHash),
	}
	res := v.VerifyLayerSignature(context.Background(), "sha256:layerdigest", []byte("fake-layer-blob"), sampleRootHash, sig)
	expectPass(t, res)
	if res.ComputedHash != sampleRootHash {
		t.Fatalf("ComputedHash = %q, want %q", res.ComputedHash, sampleRootHash)
	}
	if res.LeafSubject == "" {
		t.Fatal("LeafSubject is empty")
	}
}

func TestVerifyLayerSignature_HappyPath_NoRecompute(t *testing.T) {
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)

	v := &LayerVerifier{
		Roots:              poolOf(root),
		Recompute:          false,
		RequireCodeSignEKU: true,
	}
	res := v.VerifyLayerSignature(context.Background(), "sha256:layerdigest", nil, sampleRootHash, sig)
	expectPass(t, res)
	if res.ComputedHash != "" {
		t.Fatalf("ComputedHash should be empty when Recompute=false; got %q", res.ComputedHash)
	}
}

func TestVerifyLayerSignature_ComputedDoesNotMatchAnnotation(t *testing.T) {
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)

	v := &LayerVerifier{
		Roots:       poolOf(root),
		Recompute:   true,
		RecomputeFn: constantHash("0000000000000000000000000000000000000000000000000000000000000000"),
	}
	res := v.VerifyLayerSignature(context.Background(), "sha256:layerdigest", []byte("blob"), sampleRootHash, sig)
	expectFailContains(t, res, "does not match annotation")
}

func TestVerifyLayerSignature_SignedHashDoesNotMatchAnnotation_NoRecompute(t *testing.T) {
	// Sign for hash A, but pass annotation B with --no-recompute.
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	hashA := sampleRootHash
	hashB := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, hashA)

	v := &LayerVerifier{
		Roots:     poolOf(root),
		Recompute: false,
	}
	res := v.VerifyLayerSignature(context.Background(), "sha256:layerdigest", nil, hashB, sig)
	expectFailContains(t, res, "rsa.VerifyPKCS1v15")
}

func TestVerifyLayerSignature_AnnotatedHash_NotHex(t *testing.T) {
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)
	v := &LayerVerifier{Roots: poolOf(root)}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, "notvalidhex--------------------------------------------------------", sig)
	expectFailContains(t, res, "is not 64-char lowercase hex")
}

func TestVerifyLayerSignature_AnnotatedHash_Uppercase(t *testing.T) {
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)
	upper := strings.ToUpper(sampleRootHash)
	v := &LayerVerifier{Roots: poolOf(root)}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, upper, sig)
	expectFailContains(t, res, "is not 64-char lowercase hex")
}

func TestVerifyLayerSignature_EmptySig(t *testing.T) {
	root, _, _, _ := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	v := &LayerVerifier{Roots: poolOf(root)}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, sampleRootHash, nil)
	expectFailContains(t, res, "PKCS#7 signature is empty")
}

func TestVerifyLayerSignature_MalformedPKCS7(t *testing.T) {
	root, _, _, _ := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	v := &LayerVerifier{Roots: poolOf(root)}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, sampleRootHash, []byte("not-pkcs7-bytes"))
	expectFailContains(t, res, "parse PKCS#7")
}

func TestVerifyLayerSignature_WrongCA(t *testing.T) {
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)

	other, _, _, _ := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	v := &LayerVerifier{Roots: poolOf(other)}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, sampleRootHash, sig)
	expectFailContains(t, res, "x509 chain verify")
}

func TestVerifyLayerSignature_ExpiredCert(t *testing.T) {
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)
	v := &LayerVerifier{
		Roots: poolOf(root),
		Now:   time.Now().Add(48 * time.Hour),
	}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, sampleRootHash, sig)
	expectFailContains(t, res, "x509 chain verify")
}

func TestVerifyLayerSignature_NoEKU_RequiredExplicit(t *testing.T) {
	// Go's x509.Verify treats "no EKU at all" as valid for any usage. Our
	// explicit RequireCodeSignEKU check should still reject it.
	root, _, leafCert, leafKey := newTestPKI(t, withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)) /* no EKU */)
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)
	v := &LayerVerifier{
		Roots:              poolOf(root),
		RequireCodeSignEKU: true,
	}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, sampleRootHash, sig)
	expectFailContains(t, res, "Code Signing EKU")
}

func TestVerifyLayerSignature_WrongEKU(t *testing.T) {
	// Leaf with only ServerAuth EKU; x509.Verify's KeyUsages check should
	// reject it before our explicit RequireCodeSignEKU check runs.
	root, _, leafCert, leafKey := newTestPKI(t, withEKU(x509.ExtKeyUsageServerAuth), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)
	v := &LayerVerifier{
		Roots:              poolOf(root),
		RequireCodeSignEKU: true,
	}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, sampleRootHash, sig)
	expectFailContains(t, res, "x509 chain verify")
}

func TestVerifyLayerSignature_RSA3072(t *testing.T) {
	// Sign side rejects non-2048, so we forge a 3072-bit envelope directly
	// via gopkcs7 to confirm the verifier also rejects it.
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(3072), withNotAfter(time.Now().Add(time.Hour)))
	sig := forgeRSAEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)
	v := &LayerVerifier{Roots: poolOf(root)}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, sampleRootHash, sig)
	expectFailContains(t, res, "RSA-3072")
}

func TestVerifyLayerSignature_NonRSA(t *testing.T) {
	// ECDSA leaf, again forged directly via gopkcs7.
	rootCert, rootKey, leafCert, leafKey := newTestECDSAPKI(t, withCodeSigningEKU(), withNotAfter(time.Now().Add(time.Hour)))
	_ = rootKey
	sig := forgeECDSAEnvelope(t, leafKey, []*x509.Certificate{leafCert, rootCert}, sampleRootHash)
	v := &LayerVerifier{Roots: poolOf(rootCert)}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, sampleRootHash, sig)
	// gopkcs7 marks ECDSA via OIDDigestAlgorithmECDSASHA256, which our
	// encryption-algorithm check (must be OIDEncryptionAlgorithmRSA) rejects.
	expectFailContains(t, res, "encryption algorithm")
}

func TestVerifyLayerSignature_RecomputeRequiresBlob(t *testing.T) {
	root, _, leafCert, leafKey := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	sig := signWithCoreEnvelope(t, leafKey, []*x509.Certificate{leafCert, root}, sampleRootHash)
	v := &LayerVerifier{
		Roots:       poolOf(root),
		Recompute:   true,
		RecomputeFn: constantHash(sampleRootHash),
	}
	res := v.VerifyLayerSignature(context.Background(), "sha256:l", nil, sampleRootHash, sig)
	expectFailContains(t, res, "layerBlob is nil")
}

// --- LoadCAPool tests ---

func TestLoadCAPool_OK(t *testing.T) {
	dir := t.TempDir()
	root, _, _, _ := newTestPKI(t, withCodeSigningEKU(), withRSABits(2048), withNotAfter(time.Now().Add(time.Hour)))
	path := filepath.Join(dir, "ca.pem")
	writePEM(t, path, "CERTIFICATE", root.Raw)

	pool, err := LoadCAPool(path)
	if err != nil {
		t.Fatalf("LoadCAPool: %v", err)
	}
	if pool == nil {
		t.Fatal("pool is nil")
	}
}

func TestLoadCAPool_Missing(t *testing.T) {
	_, err := LoadCAPool(filepath.Join(t.TempDir(), "nope.pem"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "read CA file") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestLoadCAPool_NoCertBlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	writePEM(t, path, "PRIVATE KEY", []byte("not actually a key"))

	_, err := LoadCAPool(path)
	if err == nil || !strings.Contains(err.Error(), "no CERTIFICATE blocks") {
		t.Fatalf("expected 'no CERTIFICATE blocks' error, got %v", err)
	}
}

func TestLoadCAPool_Malformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	writePEM(t, path, "CERTIFICATE", []byte("not-DER-bytes"))

	_, err := LoadCAPool(path)
	if err == nil || !strings.Contains(err.Error(), "parse certificate") {
		t.Fatalf("expected 'parse certificate' error, got %v", err)
	}
}

func TestLoadCAPool_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCAPool(path)
	if err == nil || !strings.Contains(err.Error(), "no CERTIFICATE blocks") {
		t.Fatalf("expected 'no CERTIFICATE blocks' error, got %v", err)
	}
}

// --- isLowerHex256 ---

func TestIsLowerHex256(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"", false},
		{strings.Repeat("a", 63), false},
		{strings.Repeat("a", 65), false},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("0", 64), true},
		{strings.Repeat("f", 64), true},
		{strings.Repeat("g", 64), false},
		{strings.Repeat("A", 64), false},
		{"94d5c17ad918e91147e71443c5dfe2e2c95cbf27ddd7674213422801a6925d4a", true},
	}
	for _, c := range cases {
		if got := isLowerHex256(c.s); got != c.want {
			t.Errorf("isLowerHex256(%q)=%v, want %v", c.s, got, c.want)
		}
	}
}

// --- test helpers ---

type pkiOpts struct {
	eku      []x509.ExtKeyUsage
	rsaBits  int
	notAfter time.Time
}

type pkiOpt func(*pkiOpts)

func withCodeSigningEKU() pkiOpt { return withEKU(x509.ExtKeyUsageCodeSigning) }
func withEKU(eku ...x509.ExtKeyUsage) pkiOpt {
	return func(o *pkiOpts) { o.eku = append(o.eku, eku...) }
}
func withRSABits(bits int) pkiOpt    { return func(o *pkiOpts) { o.rsaBits = bits } }
func withNotAfter(t time.Time) pkiOpt { return func(o *pkiOpts) { o.notAfter = t } }

// newTestPKI returns (rootCert, rootKey, leafCert, leafKey). Root signs the
// leaf directly (no intermediate; the verifier doesn't care).
func newTestPKI(t *testing.T, opts ...pkiOpt) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	o := pkiOpts{rsaBits: 2048, notAfter: time.Now().Add(time.Hour)}
	for _, opt := range opts {
		opt(&o)
	}

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa root: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, o.rsaBits)
	if err != nil {
		t.Fatalf("rsa leaf: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  o.eku,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return rootCert, rootKey, leafCert, leafKey
}

// newTestECDSAPKI returns (rootCert, rootKey, leafCert, leafKey) with an
// ECDSA leaf (root remains RSA so the leaf has a parent signature).
func newTestECDSAPKI(t *testing.T, opts ...pkiOpt) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	o := pkiOpts{notAfter: time.Now().Add(time.Hour)}
	for _, opt := range opts {
		opt(&o)
	}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa root: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa leaf: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-ecdsa-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     o.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  o.eku,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create ecdsa leaf: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)
	return rootCert, rootKey, leafCert, leafKey
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

// constantHash returns a RecomputeFunc that always returns h.
func constantHash(h string) RecomputeFunc {
	return func(_ context.Context, _ string, _ []byte) (string, error) {
		return h, nil
	}
}

// testRSASigner satisfies signature.Signer for the canonical sign path.
type testRSASigner struct {
	key   *rsa.PrivateKey
	chain []*x509.Certificate
}

func (s *testRSASigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	digest := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, nil, err
	}
	return sig, s.chain, nil
}

func (s *testRSASigner) KeySpec() (signature.KeySpec, error) {
	return signature.KeySpec{Type: signature.KeyTypeRSA, Size: s.key.N.BitLen()}, nil
}

// signWithCoreEnvelope produces a PKCS#7 envelope via notation-core-go's
// canonical sign path (which enforces the dm-verity profile). Use this for
// all "valid envelope" test setups.
func signWithCoreEnvelope(t *testing.T, key *rsa.PrivateKey, chain []*x509.Certificate, rootHash string) []byte {
	t.Helper()
	env := corepkcs7.NewEnvelope()
	req := &signature.SignRequest{
		Signer: &testRSASigner{key: key, chain: chain},
		Payload: signature.Payload{
			ContentType: corepkcs7.MediaTypeEnvelope,
			Content:     []byte(rootHash),
		},
	}
	sig, err := env.Sign(req)
	if err != nil {
		t.Fatalf("envelope.Sign: %v", err)
	}
	return sig
}

// forgeRSAEnvelope skips notation-core-go's profile checks and produces a
// detached PKCS#7 SignedData with the given RSA key and certs, regardless of
// key size. Used to exercise the verifier's defense-in-depth rejection of
// non-2048 keys.
func forgeRSAEnvelope(t *testing.T, key *rsa.PrivateKey, chain []*x509.Certificate, rootHash string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(rootHash))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("forge sign: %v", err)
	}
	sd, err := gopkcs7.NewSignedData([]byte(rootHash))
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}
	sd.SetDigestAlgorithm(gopkcs7.OIDDigestAlgorithmSHA256)
	sd.SetEncryptionAlgorithm(gopkcs7.OIDEncryptionAlgorithmRSA)
	adapter := &basicSigner{pub: chain[0].PublicKey, sig: sig}
	if err := sd.SignWithoutAttr(chain[0], adapter, gopkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("SignWithoutAttr: %v", err)
	}
	for i := 1; i < len(chain); i++ {
		sd.AddCertificate(chain[i])
	}
	sd.Detach()
	out, err := sd.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return out
}

// forgeECDSAEnvelope produces a detached PKCS#7 SignedData with an ECDSA
// SignerInfo (OIDDigestAlgorithmECDSASHA256). Used to exercise the verifier's
// "must be RSA encryption" check.
func forgeECDSAEnvelope(t *testing.T, key *ecdsa.PrivateKey, chain []*x509.Certificate, rootHash string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(rootHash))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	sd, err := gopkcs7.NewSignedData([]byte(rootHash))
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}
	sd.SetDigestAlgorithm(gopkcs7.OIDDigestAlgorithmSHA256)
	sd.SetEncryptionAlgorithm(gopkcs7.OIDDigestAlgorithmECDSASHA256)
	adapter := &basicSigner{pub: chain[0].PublicKey, sig: sig}
	if err := sd.SignWithoutAttr(chain[0], adapter, gopkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("SignWithoutAttr: %v", err)
	}
	for i := 1; i < len(chain); i++ {
		sd.AddCertificate(chain[i])
	}
	sd.Detach()
	out, err := sd.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return out
}

// basicSigner is a minimal single-use crypto.Signer that returns a
// pre-computed signature regardless of the digest passed in. Used by the
// forge helpers so we can hand gopkcs7 an envelope that violates the
// dm-verity profile (e.g. RSA-3072, ECDSA) without going through
// notation-core-go's profile checks.
type basicSigner struct {
	pub  crypto.PublicKey
	sig  []byte
	used bool
}

func (s *basicSigner) Public() crypto.PublicKey { return s.pub }
func (s *basicSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	if s.used {
		return nil, errors.New("basicSigner reused")
	}
	s.used = true
	return s.sig, nil
}

// --- assertion helpers ---

func expectPass(t *testing.T, res LayerVerifyResult) {
	t.Helper()
	if res.Status != StatusPass {
		t.Fatalf("Status = %s, err = %v; want PASS", res.Status, res.Err)
	}
	if res.Err != nil {
		t.Fatalf("Err = %v; want nil", res.Err)
	}
}

func expectFailContains(t *testing.T, res LayerVerifyResult, substr string) {
	t.Helper()
	if res.Status != StatusFail {
		t.Fatalf("Status = %s; want FAIL", res.Status)
	}
	if res.Err == nil {
		t.Fatal("Err is nil; want non-nil")
	}
	if !strings.Contains(res.Err.Error(), substr) {
		t.Fatalf("Err = %q; want substring %q", res.Err.Error(), substr)
	}
}
