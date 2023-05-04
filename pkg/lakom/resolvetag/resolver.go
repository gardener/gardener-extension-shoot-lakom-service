// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag

import (
	"context"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/metrics"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/singleflight"
)

type directResolver struct{}

// NewDirectResolver creates new resolver and returns it.
func NewDirectResolver() *directResolver {
	dc := &directResolver{}
	return dc
}

// Resolve resolves image tag to digest.
func (r *directResolver) Resolve(ctx context.Context, tagRef name.Tag, kcr utils.KeyChainReader) (string, error) {
	keyChain, err := kcr.GetKeyChain()
	if err != nil {
		return "", err
	}

	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithUserAgent(constants.ApplicationName),
		remote.WithAuthFromKeychain(keyChain),
	}

	desc, err := remote.Head(tagRef, remoteOpts...)
	if err != nil {
		return "", err
	}

	digest := tagRef.Context().Digest(desc.Digest.String()).String()
	return digest, nil
}

type cacheResolver struct {
	cache          DigestCache
	actualResolver Resolver
	requestGroup   singleflight.Group
}

// NewCacheResolver creates cached resolver from the provided cache and resolver.
func NewCacheResolver(cache DigestCache, resolver Resolver) *cacheResolver {
	dc := &cacheResolver{
		cache:          cache,
		actualResolver: resolver,
	}
	return dc
}

// Resolve resolves image tag to digest. Firstly it checks if the cache have an entry
// for the mapping of the tag to the digest and returns it. If the cache have no entry,
// it uses the resolver to do the real resolving, persists the result in the cache and return it.
func (r *cacheResolver) Resolve(ctx context.Context, tagRef name.Tag, kcr utils.KeyChainReader) (string, error) {
	image := tagRef.Name()
	digest, found := r.cache.GetDigest(image)
	if found {
		metrics.ResolvedTagCache.WithLabelValues(metrics.CacheHit).Inc()
		return digest, nil
	}

	defer r.requestGroup.Forget(image)
	v, err, _ := r.requestGroup.Do(image, func() (any, error) {
		digest, err := r.actualResolver.Resolve(ctx, tagRef, kcr)
		if err != nil {
			return "", err
		}
		return digest, nil
	})
	if err != nil {
		return "", err
	}

	// Casting is safe here
	digest = v.(string)
	metrics.ResolvedTagCache.WithLabelValues(metrics.CacheMiss).Inc()
	r.cache.StoreDigest(image, digest)
	return digest, nil
}
