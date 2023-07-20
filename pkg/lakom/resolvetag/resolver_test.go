// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag_test

import (
	"context"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/resolvetag"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type anonymousKeyChain struct{}

func (k *anonymousKeyChain) Resolve(authn.Resource) (authn.Authenticator, error) {
	return authn.Anonymous, nil
}

type anonymousKeyChainReader struct{}

func (k *anonymousKeyChainReader) GetKeyChain() (authn.Keychain, error) {
	a := anonymousKeyChain{}
	return &a, nil
}

var _ = Describe("Resolver", func() {
	var (
		cache          resolvetag.DigestCache
		cacheResolver  resolvetag.Resolver
		refresh        = time.Millisecond * 100
		ttl            = time.Second
		kcr            = &anonymousKeyChainReader{}
		directResolver = resolvetag.NewDirectResolver()
		ctx            = context.Background()
	)

	BeforeEach(func() {
		var err error
		cache, err = resolvetag.NewDigestCache(refresh, ttl)
		Expect(err).ToNot(HaveOccurred())
		cacheResolver = resolvetag.NewCacheResolver(cache, directResolver)
	})

	Describe("Direct Resolver", func() {
		DescribeTable("Directly resolve images",
			func(image, expectedImage string, expectTagParsingError, expectResolvingError bool, errorMessage string) {
				tagRef, err := name.NewTag(image)
				if expectTagParsingError {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorMessage))
					return
				}

				Expect(err).ToNot(HaveOccurred())
				resolvedImage, err := directResolver.Resolve(ctx, tagRef, kcr)
				if expectResolvingError {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorMessage))
					return
				}

				Expect(err).ToNot(HaveOccurred())
				Expect(resolvedImage).To(Equal(expectedImage))
			},
			Entry("[GCR] Resolve tag to digest", "k8s.gcr.io/pause:3.7", "k8s.gcr.io/pause@sha256:bb6ed397957e9ca7c65ada0db5c5d1c707c9c8afc80a94acbe69f3ae76988f0c", false, false, ""),
			Entry("[Docker Hub] Resolve tag to digest", "index.docker.io/library/alpine:3.10.0", "index.docker.io/library/alpine@sha256:ca1c944a4f8486a153024d9965aafbe24f5723c1d5c02f4964c045a16d19dc54", false, false, ""),
			Entry("Do not run actual resolving of image with digest", "image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true, false, ""),
			Entry("Fail to parse bad image digest", "gardener/non-existing-image@sha256:123", "", true, false, "repository can only contain the characters `abcdefghijklmnopqrstuvwxyz0123456789_-./`"),
			Entry("Fail to parse bad image tag", "gardener/non-existing-image:123!", "", true, false, "tag can only contain the characters `abcdefghijklmnopqrstuvwxyz0123456789_-.ABCDEFGHIJKLMNOPQRSTUVWXYZ`"),
			Entry("Fail to get non-existing image", "eu.gcr.io/gardener-project/non-existing-image:123", "", false, true, "unexpected status code 404 Not Found"),
		)
	})

	Describe("Cache Resolver", func() {
		DescribeTable("Directly resolve images and ensure result is cached",
			func(image, expectedImage string, expectTagParsingError, expectResolvingError bool, errorMessage string) {
				tagRef, err := name.NewTag(image)
				if expectTagParsingError {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorMessage))
					return
				}

				Expect(err).ToNot(HaveOccurred())
				resolvedImage, err := cacheResolver.Resolve(ctx, tagRef, kcr)
				if expectResolvingError {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorMessage))
					return
				}

				Expect(err).ToNot(HaveOccurred())
				Expect(resolvedImage).To(Equal(expectedImage))
				cachedImage, got := cache.GetDigest(image)
				Expect(got).To(BeTrue())
				Expect(cachedImage).To(Equal(expectedImage))
			},
			Entry("[GCR] Resolve tag to digest", "k8s.gcr.io/pause:3.7", "k8s.gcr.io/pause@sha256:bb6ed397957e9ca7c65ada0db5c5d1c707c9c8afc80a94acbe69f3ae76988f0c", false, false, ""),
			Entry("[Docker Hub] Resolve tag to digest", "index.docker.io/library/alpine:3.10.0", "index.docker.io/library/alpine@sha256:ca1c944a4f8486a153024d9965aafbe24f5723c1d5c02f4964c045a16d19dc54", false, false, ""),
			Entry("Do not run actual resolving of image with digest", "image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "image@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true, false, ""),
			Entry("Fail to parse bad image digest", "gardener/non-existing-image@sha256:123", "", true, false, "repository can only contain the characters `abcdefghijklmnopqrstuvwxyz0123456789_-./`"),
			Entry("Fail to parse bad image tag", "gardener/non-existing-image:123!", "", true, false, "tag can only contain the characters `abcdefghijklmnopqrstuvwxyz0123456789_-.ABCDEFGHIJKLMNOPQRSTUVWXYZ`"),
			Entry("Fail to get non-existing image", "eu.gcr.io/gardener-project/non-existing-image:123", "", false, true, "unexpected status code 404 Not Found"),
		)

		It("Should uses the cache to resolve the image", func() {
			var (
				cachedImage   = "example.io/my-image:v1"
				cachedDigest  = "example.io/my-digest@sha256:abcd"
				uncachedImage = "example.io/my-image:v2"
				f             = fakeCacheResolver{
					cache: cache,
				}
			)

			imageRef, err := name.NewTag(cachedImage)
			Expect(err).ToNot(HaveOccurred())
			f.cache.StoreDigest(cachedImage, cachedDigest)

			resolved, err := f.Resolve(ctx, imageRef)
			Expect(err).ToNot(HaveOccurred())
			Expect(resolved).To(Equal(cachedDigest))
			Expect(f.cacheHits).To(BeNumerically("==", 1))
			Expect(f.cacheMisses).To(BeNumerically("==", 0))

			imageRef, err = name.NewTag(uncachedImage)
			Expect(err).ToNot(HaveOccurred())

			resolved, err = f.Resolve(ctx, imageRef)
			Expect(err).ToNot(HaveOccurred())
			Expect(resolved).To(Equal("unresolved"))
			Expect(f.cacheHits).To(BeNumerically("==", 1))
			Expect(f.cacheMisses).To(BeNumerically("==", 1))
		})

		It("Should remove cached object due to expired TTL", func() {
			var (
				key   = "foo"
				value = "bar"
			)

			_, found := cache.GetDigest(key)
			Expect(found).To(BeFalse())
			cache.StoreDigest(key, value)
			cached, found := cache.GetDigest(key)
			Expect(found).To(BeTrue())
			Expect(cached).To(Equal(value))

			Eventually(func() bool {
				_, found := cache.GetDigest(key)
				return found
			}).WithTimeout(ttl * 2).Should(BeFalse())

		})
	})
})

type fakeCacheResolver struct {
	cache       resolvetag.DigestCache
	cacheHits   uint
	cacheMisses uint
}

// Resolve implements fake cache resolver that just counts the cache hits and misses
func (r *fakeCacheResolver) Resolve(_ context.Context, tagRef name.Tag) (string, error) {
	image := tagRef.String()
	digest, found := r.cache.GetDigest(image)
	if found {
		r.cacheHits++
		return digest, nil
	}

	r.cacheMisses++

	digest = "unresolved"

	r.cache.StoreDigest(image, digest)
	return digest, nil
}
