// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature

import (
	"time"

	"github.com/gardener/service-account-issuer-discovery/pkg/cache"
)

type signatureVerificationResultCache struct {
	cache *cache.Cache
}

// NewSignatureVerificationResultCache creates and returns a SignatureVerificationResultCache.
func NewSignatureVerificationResultCache(refreshInterval, cachedObjectTTL time.Duration) (*signatureVerificationResultCache, error) {
	dc := &signatureVerificationResultCache{}
	cache, err := cache.NewCache(refreshInterval, int64(cachedObjectTTL.Seconds()))
	if err != nil {
		return dc, err
	}

	dc.cache = cache
	return dc, nil
}

// GetSignatureVerificationResult check for verification state of a given image in a cache.
// It returns the verification state as well as whether it was found in the cache.
func (dc *signatureVerificationResultCache) GetSignatureVerificationResult(image string) (bool, bool) {
	cached := dc.cache.Get(image)
	if cached == nil {
		return false, false
	}
	verified := cached[0]
	return verified == 1, true
}

// StoreSignatureVerificationResult stores the verification state for a given image in a cache.
func (dc *signatureVerificationResultCache) StoreSignatureVerificationResult(image string, verified bool) {
	var v byte
	if verified {
		v = 1
	}
	dc.cache.Update(image, []byte{v})
}
