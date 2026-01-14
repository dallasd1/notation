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

// Package pkcs7 provides PKCS#7 signature envelope creation for dm-verity root hash signing.
// The PKCS#7 format is required for kernel dm-verity verification.
package pkcs7

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/notaryproject/notation-core-go/signature"
)

// MediaType is the PKCS#7 signature envelope media type.
const MediaType = "application/pkcs7-signature"

// OIDs for PKCS#7 structures
var (
	// OIDData is the OID for PKCS#7 Data content type
	OIDData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	// OIDSignedData is the OID for PKCS#7 SignedData content type
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// Digest algorithm OIDs
	OIDDigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// RSA encryption OID (used for digestEncryptionAlgorithm in signerInfo)
	OIDEncryptionRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// ECDSA signature algorithm OIDs
	OIDSignatureECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSignatureECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSignatureECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// ASN.1 structures for PKCS#7 SignedData (RFC 2315 / RFC 5652)

// contentInfo represents the ContentInfo structure
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData represents the SignedData structure
type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               rawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

// signerInfo represents the SignerInfo structure
type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,omitempty,tag:1"`
}

// issuerAndSerial identifies the signer's certificate
type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// attribute represents a signed or unsigned attribute
type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

// rawCertificates is a set of raw certificate bytes
type rawCertificates struct {
	Raw asn1.RawContent
}

// Signer wraps notation's signature.Signer interface for PKCS#7 envelope creation.
type Signer struct {
	base    signature.Signer
	keySpec signature.KeySpec
}

// NewSigner creates a new PKCS#7 signer from a notation signature.Signer.
func NewSigner(signer signature.Signer) (*Signer, error) {
	keySpec, err := signer.KeySpec()
	if err != nil {
		return nil, fmt.Errorf("failed to get key spec: %w", err)
	}
	return &Signer{
		base:    signer,
		keySpec: keySpec,
	}, nil
}

// Sign creates a PKCS#7 SignedData envelope for the given content.
func (s *Signer) Sign(content []byte) ([]byte, error) {
	// Call the underlying signer - this goes to the plugin which:
	// 1. Hashes the content
	// 2. Signs the hash
	// 3. Returns signature + certificate chain
	sig, certs, err := s.base.Sign(content)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates returned from signer")
	}

	// Build PKCS#7 SignedData structure
	return buildSignedData(content, sig, certs, s.keySpec)
}

// buildSignedData constructs a PKCS#7 SignedData structure.
// Creates a detached signature without authenticated attributes (-noattr in OpenSSL).
func buildSignedData(content, sig []byte, certs []*x509.Certificate, keySpec signature.KeySpec) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("certificate chain is empty")
	}

	leafCert := certs[0]

	// Determine digest and signature algorithm OIDs based on key spec
	digestOID, sigOID, err := getAlgorithmOIDs(keySpec)
	if err != nil {
		return nil, err
	}

	// Build issuer and serial number from leaf certificate
	ias := issuerAndSerial{
		IssuerName:   asn1.RawValue{FullBytes: leafCert.RawIssuer},
		SerialNumber: leafCert.SerialNumber,
	}

	// Build signer info (no authenticated attributes for -noattr compatibility)
	si := signerInfo{
		Version:               1,
		IssuerAndSerialNumber: ias,
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: digestOID,
		},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: sigOID,
		},
		EncryptedDigest: sig,
		// No AuthenticatedAttributes - equivalent to OpenSSL -noattr
	}

	// Marshal all certificates
	certBytes, err := marshalCertificates(certs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificates: %w", err)
	}

	// Build the SignedData structure
	// Note: ContentInfo.Content is empty for detached signatures (dm-verity requirement).
	// The kernel provides the data separately when verifying.
	sd := signedData{
		Version: 1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{
			{Algorithm: digestOID},
		},
		ContentInfo: contentInfo{
			ContentType: OIDData,
			// Content is omitted for detached signature - kernel provides data separately
		},
		Certificates: rawCertificates{Raw: certBytes},
		SignerInfos:  []signerInfo{si},
	}

	// Marshal SignedData
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SignedData: %w", err)
	}

	// Wrap in ContentInfo
	ci := contentInfo{
		ContentType: OIDSignedData,
		Content: asn1.RawValue{
			Class:      2, // context-specific
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
		},
	}

	return asn1.Marshal(ci)
}

// getAlgorithmOIDs returns the digest and signature algorithm OIDs for the given key spec.
func getAlgorithmOIDs(keySpec signature.KeySpec) (digestOID, sigOID asn1.ObjectIdentifier, err error) {
	switch keySpec.Type {
	case signature.KeyTypeRSA:
		// All RSA key sizes use rsaEncryption for digestEncryptionAlgorithm
		// The digest algorithm (SHA-256/384/512) is specified separately
		switch keySpec.Size {
		case 2048:
			return OIDDigestAlgorithmSHA256, OIDEncryptionRSA, nil
		case 3072:
			return OIDDigestAlgorithmSHA384, OIDEncryptionRSA, nil
		case 4096:
			return OIDDigestAlgorithmSHA512, OIDEncryptionRSA, nil
		default:
			return nil, nil, fmt.Errorf("unsupported RSA key size: %d", keySpec.Size)
		}
	case signature.KeyTypeEC:
		switch keySpec.Size {
		case 256:
			return OIDDigestAlgorithmSHA256, OIDSignatureECDSASHA256, nil
		case 384:
			return OIDDigestAlgorithmSHA384, OIDSignatureECDSASHA384, nil
		case 521:
			return OIDDigestAlgorithmSHA512, OIDSignatureECDSASHA512, nil
		default:
			return nil, nil, fmt.Errorf("unsupported EC key size: %d", keySpec.Size)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %v", keySpec.Type)
	}
}

// marshalCertificates converts x509 certificates to raw DER for PKCS#7
func marshalCertificates(certs []*x509.Certificate) ([]byte, error) {
	var raw []byte
	for _, cert := range certs {
		raw = append(raw, cert.Raw...)
	}
	// Wrap in SET tag for PKCS#7
	return asn1.Marshal(asn1.RawValue{
		Class:      0,
		Tag:        17, // SET
		IsCompound: true,
		Bytes:      raw,
	})
}

// mustMarshal marshals content as an OCTET STRING, panics on error
func mustMarshal(content []byte) []byte {
	b, err := asn1.Marshal(content)
	if err != nil {
		panic(err)
	}
	return b
}
