// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
)

// lazyKeyChainReader is implementation of utils.KeyChainReader which ensures
// the image pull secrets of a pod are read only once for all containers
type lazyKeyChainReader struct {
	once           sync.Once
	keyChainReader func() (authn.Keychain, error)

	keyChain authn.Keychain
	err      error
}

func (k *lazyKeyChainReader) GetKeyChain() (authn.Keychain, error) {
	k.once.Do(func() {
		k.keyChain, k.err = k.keyChainReader()
	})

	return k.keyChain, k.err
}

// NewLazyKeyChainReader returns new lazyKeyChainReader.
func NewLazyKeyChainReader(reader func() (authn.Keychain, error)) *lazyKeyChainReader {
	return &lazyKeyChainReader{
		keyChainReader: reader,
	}
}
