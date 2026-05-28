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
	"errors"
	"fmt"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/display"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/display/output"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/experimental"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/flag"
	"github.com/notaryproject/notation/v2/cmd/notation/internal/verify"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
)

type verifyOpts struct {
	flag.LoggingFlagOpts
	flag.SecureFlagOpts
	printer              *output.Printer
	reference            string
	pluginConfig         []string
	userMetadata         []string
	ociLayout            bool
	trustPolicyScope     string
	inputType            inputType
	maxSignatureAttempts int

	// dm-verity flags (experimental)
	dmVerity    bool
	caPath      string
	noRecompute bool
}

func verifyCommand(opts *verifyOpts) *cobra.Command {
	if opts == nil {
		opts = &verifyOpts{
			inputType: inputTypeRegistry, // remote registry by default
		}
	}
	longMessage := `Verify OCI artifacts

Prerequisite: added a certificate into trust store and created a trust policy.

Example - Verify a signature on an OCI artifact identified by a digest:
  notation verify <registry>/<repository>@<digest>

Example - Verify a signature on an OCI artifact identified by a tag  (Notation will resolve tag to digest):
  notation verify <registry>/<repository>:<tag>
`
	experimentalExamples := `
Example - [Experimental] Verify a signature on an OCI artifact referenced in an OCI layout using trust policy statement specified by scope.
  notation verify --oci-layout <registry>/<repository>@<digest> --scope <trust_policy_scope>

Example - [Experimental] Verify a signature on an OCI artifact identified by a tag and referenced in an OCI layout using trust policy statement specified by scope.
  notation verify --oci-layout <registry>/<repository>:<tag> --scope <trust_policy_scope>

Example - [Experimental] Verify dm-verity layer signatures attached to an OCI image against a user-supplied CA bundle.
  notation verify --dm-verity --ca <pem-path> <registry>/<repository>@<digest>

Example - [Experimental] Verify dm-verity layer signatures without re-deriving the EROFS root hash (annotation-only, weaker integrity).
  notation verify --dm-verity --ca <pem-path> --no-recompute <registry>/<repository>@<digest>
`
	command := &cobra.Command{
		Use:   "verify [reference]",
		Short: "Verify OCI artifacts",
		Long:  longMessage,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("missing reference to the artifact: use `notation verify --help` to see what parameters are required")
			}
			opts.reference = args[0]
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if opts.ociLayout {
				opts.inputType = inputTypeOCILayout
			}
			opts.printer = output.NewPrinter(cmd.OutOrStdout(), cmd.OutOrStderr())
			if err := validateDmverityFlags(opts); err != nil {
				return err
			}
			return experimental.CheckFlagsAndWarn(cmd, "oci-layout", "scope", "dm-verity", "ca", "no-recompute")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.dmVerity {
				ctx := opts.LoggingFlagOpts.InitializeLogger(cmd.Context())
				return runVerifyDmVerity(ctx, opts)
			}
			if opts.maxSignatureAttempts <= 0 {
				return fmt.Errorf("max-signatures value %d must be a positive number", opts.maxSignatureAttempts)
			}
			return runVerify(cmd, opts)
		},
	}
	opts.LoggingFlagOpts.ApplyFlags(command.Flags())
	opts.SecureFlagOpts.ApplyFlags(command.Flags())
	command.Flags().StringArrayVar(&opts.pluginConfig, "plugin-config", nil, "{key}={value} pairs that are passed as it is to a plugin, if the verification is associated with a verification plugin, refer plugin documentation to set appropriate values")
	flag.SetPflagUserMetadata(command.Flags(), &opts.userMetadata, flag.PflagUserMetadataVerifyUsage)
	command.Flags().IntVar(&opts.maxSignatureAttempts, "max-signatures", 100, "maximum number of signatures to evaluate or examine")
	command.Flags().BoolVar(&opts.ociLayout, "oci-layout", false, "[Experimental] verify the artifact stored as OCI image layout")
	command.Flags().StringVar(&opts.trustPolicyScope, "scope", "", "[Experimental] set trust policy scope for artifact verification, required and can only be used when flag \"--oci-layout\" is set")
	command.Flags().BoolVar(&opts.dmVerity, "dm-verity", false, "[Experimental] verify dm-verity layer signatures attached as an OCI referrer instead of the standard manifest signature")
	command.Flags().StringVar(&opts.caPath, "ca", "", "[Experimental] path to a PEM file of trusted root CA certificates; required with --dm-verity")
	command.Flags().BoolVar(&opts.noRecompute, "no-recompute", false, "[Experimental] skip re-deriving the EROFS dm-verity root hash from the layer blob (weaker integrity; only proves a trusted signer signed SOME root hash)")
	command.MarkFlagsRequiredTogether("oci-layout", "scope")
	command.MarkFlagsRequiredTogether("dm-verity", "ca")
	command.MarkFlagsMutuallyExclusive("dm-verity", "oci-layout")
	experimental.HideFlags(command, experimentalExamples, []string{"oci-layout", "scope", "dm-verity", "ca", "no-recompute"})
	return command
}

// validateDmverityFlags catches the few combinations cobra MarkFlags*
// cannot express: --no-recompute without --dm-verity, an empty --ca path,
// and standard-verify-only flags that are silently ignored by the
// dm-verity verify path.
func validateDmverityFlags(opts *verifyOpts) error {
	if opts.noRecompute && !opts.dmVerity {
		return errors.New("--no-recompute is only valid with --dm-verity")
	}
	if !opts.dmVerity {
		return nil
	}
	if opts.caPath == "" {
		return errors.New("--ca must be a non-empty path when --dm-verity is set")
	}
	if len(opts.pluginConfig) > 0 || len(opts.userMetadata) > 0 {
		return errors.New("--plugin-config and --user-metadata are not used by --dm-verity (the standard notation verification flow is bypassed)")
	}
	return nil
}

func runVerify(command *cobra.Command, opts *verifyOpts) error {
	// set log level
	ctx := opts.LoggingFlagOpts.InitializeLogger(command.Context())

	// initialize
	displayHandler := display.NewVerifyHandler(opts.printer)
	sigVerifier, err := verify.GetVerifier(ctx)
	if err != nil {
		return err
	}

	// set up verification plugin config
	configs, err := flag.ParseFlagMap(opts.pluginConfig, flag.PflagPluginConfig.Name)
	if err != nil {
		return err
	}

	// set up user metadata
	userMetadata, err := flag.ParseFlagMap(opts.userMetadata, flag.PflagUserMetadata.Name)
	if err != nil {
		return err
	}

	// core verify process
	reference := opts.reference
	// always use the Referrers API, if not supported, automatically fallback to
	// the referrers tag schema
	sigRepo, err := getRepository(ctx, opts.inputType, reference, &opts.SecureFlagOpts, false)
	if err != nil {
		return err
	}
	_, resolvedRef, err := resolveReference(ctx, opts.inputType, reference, sigRepo, func(ref string, manifestDesc ocispec.Descriptor) {
		displayHandler.OnResolvingTagReference(ref)
	})
	if err != nil {
		return err
	}
	intendedRef := resolveArtifactDigestReference(resolvedRef, opts.trustPolicyScope)
	verifyOpts := notation.VerifyOptions{
		ArtifactReference:    intendedRef,
		PluginConfig:         configs,
		MaxSignatureAttempts: opts.maxSignatureAttempts,
		UserMetadata:         userMetadata,
	}
	_, outcomes, err := notation.Verify(ctx, sigVerifier, sigRepo, verifyOpts)
	err = verify.ComposeVerificationFailurePrintout(outcomes, resolvedRef, err)
	if err != nil {
		return err
	}
	displayHandler.OnVerifySucceeded(outcomes, resolvedRef)
	return displayHandler.Render()
}
