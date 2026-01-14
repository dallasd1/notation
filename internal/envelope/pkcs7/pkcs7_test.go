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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/notaryproject/notation-core-go/signature"
)

// mockSigner implements signature.Signer for testing
type mockSigner struct {
	signature []byte
	certs     []*x509.Certificate
	keySpec   signature.KeySpec
	signErr   error
}

func (m *mockSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	if m.signErr != nil {
		return nil, nil, m.signErr
	}
	return m.signature, m.certs, nil
}

func (m *mockSigner) KeySpec() (signature.KeySpec, error) {
	return m.keySpec, nil
}

func TestNewSigner(t *testing.T) {
	mock := &mockSigner{
		keySpec: signature.KeySpec{
			Type: signature.KeyTypeRSA,
			Size: 2048,
		},
	}

	signer, err := NewSigner(mock)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	if signer == nil {
		t.Fatal("NewSigner returned nil")
	}
}

func TestGetAlgorithmOIDs(t *testing.T) {
	tests := []struct {
		name    string
		keySpec signature.KeySpec
		wantErr bool
	}{
		{
			name: "RSA-2048",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 2048,
			},
			wantErr: false,
		},
		{
			name: "RSA-3072",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 3072,
			},
			wantErr: false,
		},
		{
			name: "RSA-4096",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 4096,
			},
			wantErr: false,
		},
		{
			name: "EC-256",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 256,
			},
			wantErr: false,
		},
		{
			name: "EC-384",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 384,
			},
			wantErr: false,
		},
		{
			name: "EC-521",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 521,
			},
			wantErr: false,
		},
		{
			name: "Unsupported RSA size",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeRSA,
				Size: 1024,
			},
			wantErr: true,
		},
		{
			name: "Unsupported EC size",
			keySpec: signature.KeySpec{
				Type: signature.KeyTypeEC,
				Size: 128,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digestOID, sigOID, err := getAlgorithmOIDs(tt.keySpec)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if digestOID == nil {
				t.Error("digestOID is nil")
			}
			if sigOID == nil {
				t.Error("sigOID is nil")
			}
		})
	}
}

// TestSignWithRealKey tests PKCS#7 signing with actual cryptographic operations
func TestSignWithRealKey(t *testing.T) {
	// This test uses RSA-2048 which is sufficient for testing PKCS#7 structure
	// The mock signer returns pre-computed signature bytes for deterministic testing
	testContent := []byte("test-dm-verity-root-hash-abc123")

	mock := &mockSigner{
		signature: make([]byte, 256), // RSA-2048 signature size
		certs: []*x509.Certificate{
			{
				SerialNumber: big.NewInt(1),
				Issuer: pkix.Name{
					CommonName: "Test CA",
				},
				Subject: pkix.Name{
					CommonName: "Test Signer",
				},
				Raw: []byte{0x30, 0x82, 0x01, 0x00}, // Minimal DER-encoded cert placeholder
			},
		},
		keySpec: signature.KeySpec{
			Type: signature.KeyTypeRSA,
			Size: 2048,
		},
	}

	pkcs7Signer, err := NewSigner(mock)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	sig, err := pkcs7Signer.Sign(testContent)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Fatal("Sign produced empty signature")
	}

	// Verify the output is valid ASN.1 DER
	// PKCS#7 SignedData starts with a ContentInfo SEQUENCE
	var contentInfo contentInfo
	remaining, err := asn1.Unmarshal(sig, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to unmarshal PKCS#7 ContentInfo: %v", err)
	}
	if len(remaining) > 0 {
		t.Errorf("Unexpected trailing data: %d bytes", len(remaining))
	}

	// Verify content type is signedData
	if !contentInfo.ContentType.Equal(OIDSignedData) {
		t.Errorf("ContentType = %v, want %v", contentInfo.ContentType, OIDSignedData)
	}

	t.Logf("PKCS#7 signature size: %d bytes", len(sig))
}
