// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package verifysignature_test

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/verifysignature"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	logzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
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

var _ = Describe("Verifier", func() {
	const (
		refresh = time.Millisecond * 100
		ttl     = time.Second

		// source: https://github.com/sigstore/cosign/releases/download/v1.11.1/release-cosign.pub
		cosignPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhyQCx0E9wQWSFI9ULGwy3BuRklnt
IqozONbbdbqz11hlRJy9c7SG+hdcFl9jE9uE/dwtuwU2MqU9T/cN0YkWww==
-----END PUBLIC KEY-----
`
	)

	var (
		logger      logr.Logger
		kcr         utils.KeyChainReader
		ctx         context.Context
		lakomConfig *config.CompletedConfig
	)

	BeforeEach(func() {
		logger = logzap.New(logzap.WriteTo(GinkgoWriter), logzap.UseDevMode(true))
		ctx = logf.IntoContext(context.Background(), logger)
		kcr = &anonymousKeyChainReader{}

		c := config.Config{
			PublicKeys: []config.Key{
				{
					Name:      "test",
					Key:       cosignPublicKey,
					Algorithm: config.RSAPKCS1v15SHA256,
				},
			},
		}

		l, err := c.Complete()
		Expect(err).ToNot(HaveOccurred())

		lakomConfig = l
	})

	Describe("Direct Verifier", func() {
		var (
			directVerifier verifysignature.Verifier
		)
		BeforeEach(func() {
			keys, err := utils.GetCosignPublicKeys([]byte(cosignPublicKey))
			Expect(err).ToNot(HaveOccurred())
			Expect(keys).ToNot(BeZero())

			directVerifier = verifysignature.NewDirectVerifier(*lakomConfig, false)
		})

		DescribeTable("Verify images",
			func(image string, expectedVerificationResult, expectErr bool, errorMessage string) {
				verified, err := directVerifier.Verify(ctx, image, kcr)
				if expectErr {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorMessage))
				} else {
					Expect(err).ToNot(HaveOccurred())
					Expect(verified).To(Equal(expectedVerificationResult))
				}
			},
			Entry("Fail to parse bad image digest", "gardener/non-existing-image@sha256:123", false, true, "could not parse reference"),
			Entry("Fail to parse bad image tag", "gardener/non-existing-image:123!", false, true, "could not parse reference"),
			Entry("Refuse to verify image not using digest", "registry.k8s.io/pause:3.7", false, true, "image reference is not a digest"),
			Entry("Successfully verify signed image", "gcr.io/projectsigstore/cosign@sha256:f9fd5a287a67f4b955d08062a966df10f9a600b6b8583fd367bce3f1f000a429", true, false, ""),
			Entry("Successfully verify unsigned image", "europe-docker.pkg.dev/gardener-project/releases/gardener/apiserver@sha256:249ea7f1d0439a94893b486e7820f6f0ab52522c5f22e1bad21782d6381e739e", false, false, ""),
		)

		It("Should fail image verification when context is canceled", func() {
			canceledCtx, cancel := context.WithCancel(ctx)
			cancel()

			verified, err := directVerifier.Verify(canceledCtx, "europe-docker.pkg.dev/gardener-project/releases/gardener/apiserver@sha256:249ea7f1d0439a94893b486e7820f6f0ab52522c5f22e1bad21782d6381e739e", kcr)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("context canceled"))
			Expect(verified).To(BeFalse())
		})
	})

	Describe("Cached Verifier", func() {
		var (
			cache          verifysignature.SignatureVerificationResultCache
			cachedVerifier verifysignature.Verifier
		)
		BeforeEach(func() {
			keys, err := utils.GetCosignPublicKeys([]byte(cosignPublicKey))
			Expect(err).ToNot(HaveOccurred())
			Expect(keys).ToNot(BeZero())

			cache, err = verifysignature.NewSignatureVerificationResultCache(refresh, ttl)
			Expect(err).ToNot(HaveOccurred())

			directVerifier := verifysignature.NewDirectVerifier(*lakomConfig, false)
			cachedVerifier = verifysignature.NewCacheVerifier(cache, directVerifier)
		})

		DescribeTable("Verify images",
			func(image string, expectedVerificationResult, expectErr bool, errorMessage string) {
				_, got := cache.GetSignatureVerificationResult(image)
				Expect(got).To(BeFalse())

				verified, err := cachedVerifier.Verify(ctx, image, kcr)
				if expectErr {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring(errorMessage))

					_, got := cache.GetSignatureVerificationResult(image)
					Expect(got).To(BeFalse())
				} else {
					Expect(err).ToNot(HaveOccurred())
					Expect(verified).To(Equal(expectedVerificationResult))

					cachedResult, got := cache.GetSignatureVerificationResult(image)
					Expect(got).To(BeTrue())
					Expect(cachedResult).To(Equal(verified))
				}
			},
			Entry("Fail to parse bad image digest", "gardener/non-existing-image@sha256:123", false, true, "could not parse reference"),
			Entry("Fail to parse bad image tag", "gardener/non-existing-image:123!", false, true, "could not parse reference"),
			Entry("Refuse to verify image not using digest", "registry.k8s.io/pause:3.7", false, true, "image reference is not a digest"),
			Entry("Successfully verify signed image", "gcr.io/projectsigstore/cosign@sha256:f9fd5a287a67f4b955d08062a966df10f9a600b6b8583fd367bce3f1f000a429", true, false, ""),
			Entry("Successfully verify unsigned image", "europe-docker.pkg.dev/gardener-project/releases/gardener/apiserver@sha256:249ea7f1d0439a94893b486e7820f6f0ab52522c5f22e1bad21782d6381e739e", false, false, ""),
		)

		It("Should not run real validation for cached result", func() {
			var (
				invalidImageRef               = "invalid-image-reference:123!"
				invalidImageVerificationState = true
			)

			cache.StoreSignatureVerificationResult(invalidImageRef, invalidImageVerificationState)
			verified, err := cachedVerifier.Verify(ctx, invalidImageRef, kcr)
			Expect(err).ToNot(HaveOccurred())
			Expect(verified).To(Equal(invalidImageVerificationState))

		})

		It("Should not cache failed image verification when context is canceled", func() {
			canceledCtx, cancel := context.WithCancel(ctx)
			cancel()

			image := "europe-docker.pkg.dev/gardener-project/releases/gardener/apiserver@sha256:249ea7f1d0439a94893b486e7820f6f0ab52522c5f22e1bad21782d6381e739e" // #nosec G101
			verified, err := cachedVerifier.Verify(canceledCtx, image, kcr)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("context canceled"))
			Expect(verified).To(BeFalse())

			verifiedCache, found := cache.GetSignatureVerificationResult(image)
			Expect(found).To(BeFalse())
			Expect(verifiedCache).To(BeFalse())
		})
	})

	It("Should detect NoMatchingSignature error", func() {
		noMatchingSignature := &cosign.ErrNoMatchingSignatures{}

		Expect(verifysignature.IsNoMatchingSignatures(noMatchingSignature)).To(BeTrue())
		Expect(verifysignature.IsNoMatchingSignatures(fmt.Errorf("some other error"))).To(BeFalse())
	})

	It("Should detect NoSignaturesFound error", func() {
		noSignaturesFound := &cosign.ErrNoSignaturesFound{}

		Expect(verifysignature.IsNoSignaturesFound(noSignaturesFound)).To(BeTrue())
		Expect(verifysignature.IsNoSignaturesFound(fmt.Errorf("some other error"))).To(BeFalse())
	})

})
