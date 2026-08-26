// SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"github.com/google/go-containerregistry/pkg/authn"
)

// KeyChainReader returns key chain for OCI registry.
type KeyChainReader interface {
	GetKeyChain() (authn.Keychain, error)
}
