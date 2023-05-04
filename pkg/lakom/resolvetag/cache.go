// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag

import (
	"time"

	"github.com/gardener/service-account-issuer-discovery/pkg/cache"
)

type digestCache struct {
	cache *cache.Cache
}

// NewDigestCache constructs new cache for image tags to digests and returns it.
func NewDigestCache(refreshInterval, cachedObjectTTL time.Duration) (*digestCache, error) {
	dc := &digestCache{}
	cache, err := cache.NewCache(refreshInterval, int64(cachedObjectTTL.Seconds()))
	if err != nil {
		return dc, err
	}

	dc.cache = cache
	return dc, nil
}

// GetDigest check for the digest if image tag in a cache.
// It returns the image digest as well as whether it was found in the cache.
func (dc *digestCache) GetDigest(image string) (string, bool) {
	digest := dc.cache.Get(image)
	if digest != nil {
		return string(digest), true
	}
	return "", false
}

// StoreDigest stores the image digest for a given image tag in a cache.
func (dc *digestCache) StoreDigest(image string, digest string) {
	dc.cache.Update(image, []byte(digest))
}
