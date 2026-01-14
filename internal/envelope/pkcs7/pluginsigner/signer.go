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

// Package pluginsigner provides a primitive signer that uses notation plugins for PKCS#7 signing.
package pluginsigner

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-go/plugin"
	"github.com/notaryproject/notation-go/plugin/proto"
)

const contractVersion = proto.ContractVersion

// PluginPrimitiveSigner implements signature.Signer by delegating to a plugin.
type PluginPrimitiveSigner struct {
	ctx          context.Context
	plugin       plugin.SignPlugin
	keyID        string
	pluginConfig map[string]string
	keySpec      signature.KeySpec
}

// NewPluginPrimitiveSigner creates a new primitive signer from a plugin.
func NewPluginPrimitiveSigner(
	ctx context.Context,
	signPlugin plugin.SignPlugin,
	keyID string,
	keySpec signature.KeySpec,
	pluginConfig map[string]string,
) *PluginPrimitiveSigner {
	return &PluginPrimitiveSigner{
		ctx:          ctx,
		plugin:       signPlugin,
		keyID:        keyID,
		keySpec:      keySpec,
		pluginConfig: pluginConfig,
	}
}

// Sign signs the payload using the plugin's GenerateSignature.
func (s *PluginPrimitiveSigner) Sign(payload []byte) ([]byte, []*x509.Certificate, error) {
	// Encode key spec for plugin protocol
	keySpec, err := proto.EncodeKeySpec(s.keySpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode key spec: %w", err)
	}

	// Get hash algorithm from key spec
	keySpecHash, err := proto.HashAlgorithmFromKeySpec(s.keySpec)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get hash algorithm: %w", err)
	}

	// Build plugin request
	req := &proto.GenerateSignatureRequest{
		ContractVersion: contractVersion,
		KeyID:           s.keyID,
		KeySpec:         keySpec,
		Hash:            keySpecHash,
		Payload:         payload,
		PluginConfig:    s.pluginConfig,
	}

	// Call plugin
	resp, err := s.plugin.GenerateSignature(s.ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("plugin GenerateSignature failed: %w", err)
	}

	// Verify keyID is honored
	if req.KeyID != resp.KeyID {
		return nil, nil, fmt.Errorf(
			"keyID in generateSignature response %q does not match request %q",
			resp.KeyID, req.KeyID,
		)
	}

	// Parse certificate chain from response
	certs, err := parseCertChain(resp.CertificateChain)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate chain: %w", err)
	}

	return resp.Signature, certs, nil
}

// KeySpec returns the key specification.
func (s *PluginPrimitiveSigner) KeySpec() (signature.KeySpec, error) {
	return s.keySpec, nil
}

// parseCertChain parses DER-encoded certificates into x509.Certificate objects
func parseCertChain(certChain [][]byte) ([]*x509.Certificate, error) {
	if len(certChain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	certs := make([]*x509.Certificate, len(certChain))
	for i, certBytes := range certChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}
		certs[i] = cert
	}
	return certs, nil
}

// GetKeySpecFromPlugin calls DescribeKey on the plugin to get the key specification.
func GetKeySpecFromPlugin(ctx context.Context, signPlugin plugin.SignPlugin, keyID string, pluginConfig map[string]string) (signature.KeySpec, error) {
	req := &proto.DescribeKeyRequest{
		ContractVersion: contractVersion,
		KeyID:           keyID,
		PluginConfig:    pluginConfig,
	}

	resp, err := signPlugin.DescribeKey(ctx, req)
	if err != nil {
		return signature.KeySpec{}, fmt.Errorf("plugin DescribeKey failed: %w", err)
	}

	keySpec, err := proto.DecodeKeySpec(resp.KeySpec)
	if err != nil {
		return signature.KeySpec{}, fmt.Errorf("failed to decode key spec: %w", err)
	}

	return keySpec, nil
}
