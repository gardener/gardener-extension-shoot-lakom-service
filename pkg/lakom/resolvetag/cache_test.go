// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package resolvetag_test

import (
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/resolvetag"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cache", func() {

	DescribeTable(
		"Cache initialization",
		func(refreshInterval, objectTTL time.Duration, expectError bool) {
			_, err := resolvetag.NewDigestCache(refreshInterval, objectTTL)
			if expectError {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
		},
		Entry("successful initialization", time.Millisecond, time.Second, false),
		Entry("failed initialization", time.Second*2, time.Second, true),
	)

	It("Should successfully use cache", func() {
		var (
			refreshTime = time.Millisecond * 100
			ttl         = time.Second
			image       = "image"
			digest      = "digest"
		)

		By("Create cache")
		cache, err := resolvetag.NewDigestCache(refreshTime, ttl)
		Expect(err).ToNot(HaveOccurred())

		By("Ensure object is not cached")
		cachedDigest, got := cache.GetDigest(image)
		Expect(got).To(BeFalse())
		Expect(cachedDigest).To(BeEmpty())

		By("Store object in cache")
		cache.StoreDigest(image, digest)

		By("Ensure the same object can be retrieved from cache")
		cachedDigest, got = cache.GetDigest(image)
		Expect(got).To(BeTrue())
		Expect(cachedDigest).To(Equal(digest))

		By("Ensure the object will expire and will be removed from cache")
		Eventually(
			func() bool {
				_, got := cache.GetDigest(image)
				return got
			},
			(ttl + 2*refreshTime).String(),
		).Should(BeFalse())

		By("Ensure cached object can be overwritten")
		concatDigest := digest + digest
		cache.StoreDigest(image, digest)
		cachedDigest, got = cache.GetDigest(image)
		Expect(got).To(BeTrue())
		Expect(cachedDigest).To(Equal(digest))

		cache.StoreDigest(image, concatDigest)
		cachedDigest, got = cache.GetDigest(image)
		Expect(got).To(BeTrue())
		Expect(cachedDigest).ToNot(Equal(digest))
		Expect(cachedDigest).To(Equal(concatDigest))
	})
})
