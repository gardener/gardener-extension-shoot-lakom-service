// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature_test

import (
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/verifysignature"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cache", func() {

	DescribeTable(
		"Cache initialization",
		func(refreshInterval, objectTTL time.Duration, expectError bool) {
			_, err := verifysignature.NewSignatureVerificationResultCache(refreshInterval, objectTTL)
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
			refreshTime                 = time.Millisecond * 100
			ttl                         = time.Second
			image                       = "image"
			signatureVerificationResult = true
		)

		By("Create cache")
		cache, err := verifysignature.NewSignatureVerificationResultCache(refreshTime, ttl)
		Expect(err).ToNot(HaveOccurred())

		By("Ensure object is not cached")
		_, got := cache.GetSignatureVerificationResult(image)
		Expect(got).To(BeFalse())

		By("Store object in cache")
		cache.StoreSignatureVerificationResult(image, signatureVerificationResult)

		By("Ensure the same object can be retrieved from cache")
		cachedSignatureVerificationResult, got := cache.GetSignatureVerificationResult(image)
		Expect(got).To(BeTrue())
		Expect(cachedSignatureVerificationResult).To(Equal(signatureVerificationResult))

		By("Ensure the object will expire and will be removed from cache")
		Eventually(
			func() bool {
				_, got := cache.GetSignatureVerificationResult(image)
				return got
			},
			(ttl + 2*refreshTime).String(),
		).Should(BeFalse())

		By("Ensure cached object can be overwritten")
		inverseResult := !signatureVerificationResult
		cache.StoreSignatureVerificationResult(image, signatureVerificationResult)
		cachedResult, got := cache.GetSignatureVerificationResult(image)
		Expect(got).To(BeTrue())
		Expect(cachedResult).To(Equal(signatureVerificationResult))

		cache.StoreSignatureVerificationResult(image, inverseResult)
		cachedResult, got = cache.GetSignatureVerificationResult(image)
		Expect(got).To(BeTrue())
		Expect(cachedResult).ToNot(Equal(signatureVerificationResult))
		Expect(cachedResult).To(Equal(inverseResult))
	})
})
