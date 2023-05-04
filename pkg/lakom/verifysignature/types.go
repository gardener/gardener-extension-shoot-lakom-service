// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature

import (
	"context"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"
)

// Verifier is interface which implementations should verify cosign signatures of an image.
type Verifier interface {
	Verify(context.Context, string, utils.KeyChainReader) (bool, error)
}

// SignatureVerificationResultCache is interface which implementations should store the signature verification status of an image.
type SignatureVerificationResultCache interface {
	GetSignatureVerificationResult(string) (bool, bool)
	StoreSignatureVerificationResult(string, bool)
}
