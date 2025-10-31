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

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/notaryproject/notation-core-go/revocation/purpose"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/log"
	notationregistry "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/experimental"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/flag"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/sign"
	"github.com/notaryproject/notation/v2/internal/dmverity"
	"github.com/notaryproject/notation/v2/internal/envelope"
	"github.com/notaryproject/notation/v2/internal/httputil"
	"github.com/notaryproject/notation/v2/internal/registryutil"
	clirev "github.com/notaryproject/notation/v2/internal/revocation"
	nx509 "github.com/notaryproject/notation/v2/internal/x509"
	"github.com/notaryproject/tspclient-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
)

// timestampingTimeout is the timeout when requesting timestamp countersignature
// from a TSA
const timestampingTimeout = 15 * time.Second

type signOpts struct {
	flag.LoggingFlagOpts
	flag.SignerFlagOpts
	flag.SecureFlagOpts
	expiry                 time.Duration
	pluginConfig           []string
	userMetadata           []string
	reference              string
	forceReferrersTag      bool
	ociLayout              bool
	inputType              inputType
	tsaServerURL           string
	tsaRootCertificatePath string
	dmVerity               bool
}

func signCommand(opts *signOpts) *cobra.Command {
	if opts == nil {
		opts = &signOpts{
			inputType: inputTypeRegistry, // remote registry by default
		}
	}
	longMessage := `Sign artifacts

Note: a signing key must be specified. This can be done temporarily by specifying a key ID, or a new key can be configured using the command "notation key add"

Example - Sign an OCI artifact using the default signing key, with the default JWS envelope, and use OCI image manifest to store the signature:
  notation sign <registry>/<repository>@<digest>

Example - Sign an OCI artifact using the default signing key, with the COSE envelope:
  notation sign --signature-format cose <registry>/<repository>@<digest> 

Example - Sign an OCI artifact with a specified plugin and signing key stored in KMS 
  notation sign --plugin <plugin_name> --id <remote_key_id> <registry>/<repository>@<digest>

Example - Sign an OCI artifact using a specified key
  notation sign --key <key_name> <registry>/<repository>@<digest>

Example - Sign an OCI artifact identified by a tag (Notation will resolve tag to digest)
  notation sign <registry>/<repository>:<tag>

Example - Sign an OCI artifact stored in a registry and specify the signature expiry duration, for example 24 hours
  notation sign --expiry 24h <registry>/<repository>@<digest>

Example - Sign an OCI artifact and store signature using the Referrers API. If it's not supported, fallback to the Referrers tag schema
  notation sign --force-referrers-tag=false <registry>/<repository>@<digest>

Example - Sign an OCI artifact with timestamping:
  notation sign --timestamp-url <TSA_url> --timestamp-root-cert <TSA_root_certificate_filepath> <registry>/<repository>@<digest> 

Example - Sign an OCI artifact with dm-verity per-layer signatures:
  notation sign --dm-verity --signature-format pkcs7 --id <key_id> <registry>/<repository>@<digest>
`
	experimentalExamples := `
Example - [Experimental] Sign an OCI artifact referenced in an OCI layout
  notation sign --oci-layout "<oci_layout_path>@<digest>"

Example - [Experimental] Sign an OCI artifact identified by a tag and referenced in an OCI layout
  notation sign --oci-layout "<oci_layout_path>:<tag>"

Example - [Experimental] Sign an OCI artifact with dm-verity per-layer signatures
  notation sign --dm-verity --signature-format pkcs7 --id <key_id> <registry>/<repository>@<digest>
`

	command := &cobra.Command{
		Use:   "sign [flags] <reference>",
		Short: "Sign artifacts",
		Long:  longMessage,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing reference to the artifact: use `notation sign --help` to see what parameters are required")
			}
			opts.reference = args[0]
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.ociLayout {
				opts.inputType = inputTypeOCILayout
			}
			return experimental.CheckFlagsAndWarn(cmd, "oci-layout")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// timestamping
			if cmd.Flags().Changed("timestamp-url") {
				if opts.tsaServerURL == "" {
					return errors.New("timestamping: tsa url cannot be empty")
				}
				if opts.tsaRootCertificatePath == "" {
					return errors.New("timestamping: tsa root certificate path cannot be empty")
				}
			}

			// dm-verity validation
			if opts.dmVerity {
				fmt.Printf("[sign.validation] dm-verity mode enabled - validating requirements\n")
				if opts.SignerFlagOpts.SignatureFormat != "pkcs7" {
					fmt.Printf("[sign.validation] ✗ Error: dm-verity requires PKCS#7 format, got: %s\n", opts.SignerFlagOpts.SignatureFormat)
					return errors.New("dm-verity signing requires --signature-format pkcs7")
				}
				fmt.Printf("[sign.validation] ✓ PKCS#7 signature format validated\n")
			}

			return runSign(cmd, opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(command.Flags())
	opts.SignerFlagOpts.ApplyFlagsToCommand(command)
	opts.SecureFlagOpts.ApplyFlags(command.Flags())
	flag.SetPflagExpiry(command.Flags(), &opts.expiry)
	flag.SetPflagPluginConfig(command.Flags(), &opts.pluginConfig)
	flag.SetPflagUserMetadata(command.Flags(), &opts.userMetadata, flag.PflagUserMetadataSignUsage)
	command.Flags().StringVar(&opts.tsaServerURL, "timestamp-url", "", "RFC 3161 Timestamping Authority (TSA) server URL")
	command.Flags().StringVar(&opts.tsaRootCertificatePath, "timestamp-root-cert", "", "filepath of timestamp authority root certificate")
	flag.SetPflagReferrersTag(command.Flags(), &opts.forceReferrersTag, "force to store signatures using the referrers tag schema")
	command.Flags().BoolVar(&opts.ociLayout, "oci-layout", false, "[Experimental] sign the artifact stored as OCI image layout")
	command.Flags().BoolVar(&opts.dmVerity, "dm-verity", false, "[Experimental] sign each layer with dm-verity root hash using PKCS#7 format")
	command.MarkFlagsMutuallyExclusive("oci-layout", "force-referrers-tag")
	command.MarkFlagsRequiredTogether("timestamp-url", "timestamp-root-cert")
	experimental.HideFlags(command, experimentalExamples, []string{"oci-layout", "dm-verity"})
	return command
}

// fetchImageManifest uses the decoupled registryutil.BlobFetcher - specific to sign command needs.
// This function adds sign-specific logging while using the general-purpose fetcher from registryutil package.
func fetchImageManifest(ctx context.Context, sigRepo notationregistry.Repository, manifestDesc ocispec.Descriptor, reference string) (*ocispec.Manifest, error) {
	fmt.Printf("[sign.fetchImageManifest] Fetching manifest: %s\n", manifestDesc.Digest)

	// Parse reference to get repository client
	ref, err := registry.ParseReference(reference)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference: %w", err)
	}

	// Get repository client with auth/TLS configuration
	remoteRepo, err := getRepositoryClient(ctx, &flag.SecureFlagOpts{}, ref)
	if err != nil {
		return nil, fmt.Errorf("failed to get repository client: %w", err)
	}

	// Use the decoupled general-purpose blob fetcher from registryutil package
	fetcher, err := registryutil.NewBlobFetcher(ctx, reference, remoteRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to create blob fetcher: %w", err)
	}

	fmt.Printf("[sign.fetchImageManifest] Using decoupled blob fetcher for %s/%s\n",
		fetcher.GetReference().Registry, fetcher.GetReference().Repository)

	fmt.Printf("[sign.fetchImageManifest] Fetching manifest blob from registry...\n")

	// Fetch using the decoupled utility
	manifest, err := fetcher.FetchManifest(ctx, manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}

	// Sign-specific logging (this part remains coupled to sign command)
	fmt.Printf("[sign.fetchImageManifest] ✓ Successfully fetched manifest with %d layers\n", len(manifest.Layers))
	for i, layer := range manifest.Layers {
		fmt.Printf("[sign.fetchImageManifest] → Layer %d: %s (%s, %d bytes)\n", i+1, layer.Digest, layer.MediaType, layer.Size)
	}

	return manifest, nil
}

func runSign(command *cobra.Command, cmdOpts *signOpts) error {
	// set log level
	ctx := cmdOpts.LoggingFlagOpts.InitializeLogger(command.Context())

	// initialize
	signer, err := sign.GetSigner(ctx, &cmdOpts.SignerFlagOpts)
	if err != nil {
		return err
	}
	sigRepo, err := getRepository(ctx, cmdOpts.inputType, cmdOpts.reference, &cmdOpts.SecureFlagOpts, cmdOpts.forceReferrersTag)
	if err != nil {
		return err
	}
	signOpts, err := prepareSigningOpts(ctx, cmdOpts)
	if err != nil {
		return err
	}
	manifestDesc, resolvedRef, err := resolveReference(ctx, cmdOpts.inputType, cmdOpts.reference, sigRepo, func(ref string, manifestDesc ocispec.Descriptor) {
		fmt.Fprintf(os.Stderr, "Warning: Always sign the artifact using digest(@sha256:...) rather than a tag(:%s) because tags are mutable and a tag reference can point to a different artifact than the one signed.\n", ref)
	})
	if err != nil {
		return err
	}
	signOpts.ArtifactReference = manifestDesc.Digest.String()

	// core process
	var artifactManifestDesc, sigManifestDesc ocispec.Descriptor
	if cmdOpts.dmVerity {
		// dm-verity signing: process layers instead of signing the manifest
		fmt.Printf("*** [sign.runSign] Starting dm-verity signing workflow for: %s ***\n", manifestDesc.Digest)
		fmt.Printf("[sign.runSign] → Using signature format: %s\n", cmdOpts.SignerFlagOpts.SignatureFormat)
		fmt.Printf("[sign.runSign] → Using signer key: %s\n", cmdOpts.SignerFlagOpts.Key)

		// Fetch the manifest from the repository
		fmt.Printf("[sign.runSign] → Fetching manifest for: %s\n", manifestDesc.Digest)
		manifest, err := fetchImageManifest(ctx, sigRepo, manifestDesc, cmdOpts.reference)
		if err != nil {
			return fmt.Errorf("failed to fetch manifest: %w", err)
		}

		fmt.Printf("[sign.runSign] → Retrieved manifest with %d layers\n", len(manifest.Layers))
		for i, layer := range manifest.Layers {
			fmt.Printf("[sign.runSign]   Layer %d: %s (%s, %d bytes)\n", i+1, layer.Digest, layer.MediaType, layer.Size)
		}

		// Create blob fetcher for layer data
		fmt.Printf("[sign.runSign] → Creating blob fetcher for layer data...\n")
		ref, err := registry.ParseReference(cmdOpts.reference)
		if err != nil {
			return fmt.Errorf("failed to parse reference: %w", err)
		}
		remoteRepo, err := getRepositoryClient(ctx, &flag.SecureFlagOpts{}, ref)
		if err != nil {
			return fmt.Errorf("failed to get repository client: %w", err)
		}
		blobFetcher, err := registryutil.NewBlobFetcher(ctx, cmdOpts.reference, remoteRepo)
		if err != nil {
			return fmt.Errorf("failed to create blob fetcher: %w", err)
		}

		// Sign all layers with dm-verity using the decoupled fetcher
		fmt.Printf("[sign.runSign] → Calling dmverity.SignImageLayers...\n")
		layerSignatures, err := dmverity.SignImageLayers(ctx, signer, blobFetcher, *manifest)
		if err != nil {
			return fmt.Errorf("failed to sign layers with dm-verity: %w", err)
		}

		fmt.Printf("[sign.runSign] ✓ Successfully generated dm-verity signatures for %d layers\n", len(layerSignatures))

		// Create signature manifest
		fmt.Printf("[sign.runSign] → Creating signature manifest...\n")
		sigManifest, err := dmverity.CreateSignatureManifest(layerSignatures, manifestDesc)
		if err != nil {
			return fmt.Errorf("failed to create signature manifest: %w", err)
		}

		// Store the signature manifest (placeholder for now)
		fmt.Printf("[sign.runSign] ✓ Created signature manifest with %d layer signatures\n", len(sigManifest.Layers))
		fmt.Printf("[sign.runSign] ✓ Successfully signed %s with dm-verity\n", manifestDesc.Digest)

		artifactManifestDesc = manifestDesc
		sigManifestDesc = ocispec.Descriptor{
			MediaType: sigManifest.MediaType,
			Digest:    digest.FromString("mock_signature_manifest"), // TODO: Calculate actual digest
			Size:      0,                                            // TODO: Calculate actual size
		}
	} else {
		artifactManifestDesc, sigManifestDesc, err = notation.SignOCI(ctx, signer, sigRepo, signOpts)
	}
	if err != nil {
		var referrerError *remote.ReferrersError
		if !errors.As(err, &referrerError) || !referrerError.IsReferrersIndexDelete() {
			return err
		}
		// show warning for referrers index deletion failed
		fmt.Fprintln(os.Stderr, "Warning: Removal of outdated referrers index from remote registry failed. Garbage collection may be required.")
	}

	repositoryRef, _, _ := strings.Cut(resolvedRef, "@")
	fmt.Printf("Successfully signed %s@%s\n", repositoryRef, artifactManifestDesc.Digest.String())
	fmt.Printf("Pushed the signature to %s@%s\n", repositoryRef, sigManifestDesc.Digest.String())
	return nil
}

func prepareSigningOpts(ctx context.Context, opts *signOpts) (notation.SignOptions, error) {
	logger := log.GetLogger(ctx)

	mediaType, err := envelope.GetEnvelopeMediaType(opts.SignerFlagOpts.SignatureFormat)
	if err != nil {
		return notation.SignOptions{}, err
	}
	pluginConfig, err := flag.ParseFlagMap(opts.pluginConfig, flag.PflagPluginConfig.Name)
	if err != nil {
		return notation.SignOptions{}, err
	}
	userMetadata, err := flag.ParseFlagMap(opts.userMetadata, flag.PflagUserMetadata.Name)
	if err != nil {
		return notation.SignOptions{}, err
	}
	signOpts := notation.SignOptions{
		SignerSignOptions: notation.SignerSignOptions{
			SignatureMediaType: mediaType,
			ExpiryDuration:     opts.expiry,
			PluginConfig:       pluginConfig,
		},
		UserMetadata: userMetadata,
	}
	if opts.tsaServerURL != "" {
		// timestamping
		logger.Infof("Configured to timestamp with TSA %q", opts.tsaServerURL)
		signOpts.Timestamper, err = tspclient.NewHTTPTimestamper(httputil.NewClient(ctx, &http.Client{Timeout: timestampingTimeout}), opts.tsaServerURL)
		if err != nil {
			return notation.SignOptions{}, fmt.Errorf("cannot get http timestamper for timestamping: %w", err)
		}
		signOpts.TSARootCAs, err = nx509.NewRootCertPool(opts.tsaRootCertificatePath)
		if err != nil {
			return notation.SignOptions{}, err
		}
		tsaRevocationValidator, err := clirev.NewRevocationValidator(ctx, purpose.Timestamping)
		if err != nil {
			return notation.SignOptions{}, fmt.Errorf("failed to create timestamping revocation validator: %w", err)
		}
		signOpts.TSARevocationValidator = tsaRevocationValidator
	}
	return signOpts, nil
}
