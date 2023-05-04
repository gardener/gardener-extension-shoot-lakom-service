// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
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
