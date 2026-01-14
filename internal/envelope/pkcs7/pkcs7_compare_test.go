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

package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
)

// testPrimitiveSigner implements signature.Signer for testing
type testPrimitiveSigner struct {
	key     crypto.PrivateKey
	certs   []*x509.Certificate
	keySpec signature.KeySpec
}

func (s *testPrimitiveSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	// Determine hash algorithm from key spec
	var hash crypto.Hash
	switch s.keySpec.Size {
	case 256:
		hash = crypto.SHA256
	case 384:
		hash = crypto.SHA384
	case 512, 521:
		hash = crypto.SHA512
	default:
		hash = crypto.SHA256
	}

	h := hash.New()
	h.Write(payload)
	digest := h.Sum(nil)

	// Sign based on key type
	switch k := s.key.(type) {
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, hash, digest)
		if err != nil {
			return nil, nil, err
		}
		return sig, s.certs, nil
	default:
		return nil, nil, nil
	}
}

func (s *testPrimitiveSigner) KeySpec() (signature.KeySpec, error) {
	return s.keySpec, nil
}

// TestCompareWithOpenSSL compares the new PKCS#7 implementation with OpenSSL output
func TestCompareWithOpenSSL(t *testing.T) {
	// Skip if openssl is not available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	// Generate a test RSA key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Signer",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Write key and cert to temp files for OpenSSL
	keyPEM := x509.MarshalPKCS1PrivateKey(privateKey)

	keyFile, err := os.CreateTemp("", "test-key-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(keyFile.Name())

	keyPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyPEM,
	})
	keyFile.Write(keyPEMBlock)
	keyFile.Close()

	certFile, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer os.Remove(certFile.Name())

	certPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	certFile.Write(certPEMBlock)
	certFile.Close()

	// Test data (simulated root hash)
	testData := "94d5c17ad918e91147e71443c5dfe2e2c95cbf27ddd7674213422801a6925d4a"

	// Sign with OpenSSL
	cmd := exec.Command("openssl", "smime", "-sign", "-noattr", "-binary",
		"-inkey", keyFile.Name(), "-signer", certFile.Name(), "-outform", "der")
	cmd.Stdin = strings.NewReader(testData)
	opensslSig, err := cmd.Output()
	if err != nil {
		t.Fatalf("OpenSSL signing failed: %v", err)
	}

	// Sign with new implementation
	primitiveSigner := &testPrimitiveSigner{
		key:   privateKey,
		certs: []*x509.Certificate{cert},
		keySpec: signature.KeySpec{
			Type: signature.KeyTypeRSA,
			Size: 2048,
		},
	}

	pkcs7Signer, err := NewSigner(primitiveSigner)
	if err != nil {
		t.Fatalf("failed to create PKCS#7 signer: %v", err)
	}

	newSig, err := pkcs7Signer.Sign([]byte(testData))
	if err != nil {
		t.Fatalf("new PKCS#7 signing failed: %v", err)
	}

	t.Logf("OpenSSL signature: %d bytes", len(opensslSig))
	t.Logf("New signature:     %d bytes", len(newSig))

	// Parse both signatures to compare structure
	var opensslCI, newCI contentInfo
	_, err = asn1.Unmarshal(opensslSig, &opensslCI)
	if err != nil {
		t.Fatalf("failed to parse OpenSSL signature: %v", err)
	}

	_, err = asn1.Unmarshal(newSig, &newCI)
	if err != nil {
		t.Fatalf("failed to parse new signature: %v", err)
	}

	// Compare content types
	if !opensslCI.ContentType.Equal(newCI.ContentType) {
		t.Errorf("ContentType mismatch: OpenSSL=%v, New=%v", opensslCI.ContentType, newCI.ContentType)
	}

	// Both should be SignedData
	if !newCI.ContentType.Equal(OIDSignedData) {
		t.Errorf("New signature ContentType is not SignedData: %v", newCI.ContentType)
	}

	t.Logf("OpenSSL ContentType: %v", opensslCI.ContentType)
	t.Logf("New ContentType:     %v", newCI.ContentType)

	// Verify OpenSSL can parse the new signature
	newSigFile, _ := os.CreateTemp("", "new-sig-*.der")
	defer os.Remove(newSigFile.Name())
	newSigFile.Write(newSig)
	newSigFile.Close()

	verifyCmd := exec.Command("openssl", "pkcs7", "-in", newSigFile.Name(), "-inform", "der", "-print_certs", "-noout")
	verifyOut, err := verifyCmd.CombinedOutput()
	if err != nil {
		t.Errorf("OpenSSL failed to parse new signature: %v\n%s", err, string(verifyOut))
	} else {
		t.Log("OpenSSL successfully parsed new signature")
	}

	// Verify the signature actually validates
	verifyDataCmd := exec.Command("openssl", "smime", "-verify", "-noverify",
		"-in", newSigFile.Name(), "-inform", "der", "-content", "/dev/stdin")
	verifyDataCmd.Stdin = strings.NewReader(testData)
	var stdout, stderr bytes.Buffer
	verifyDataCmd.Stdout = &stdout
	verifyDataCmd.Stderr = &stderr
	err = verifyDataCmd.Run()
	if err != nil {
		t.Errorf("Signature verification failed: %v\nstderr: %s", err, stderr.String())
	} else {
		t.Log("Signature verification: OK")
	}
}

// Unused - using encoding/pem instead
var _ = base64.StdEncoding
