// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"fmt"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	"github.com/google/go-containerregistry/pkg/authn"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Utils", func() {

	Describe("GetCosignPublicKeys", func() {
		var (
			validCosignPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC0xfVLM3nSU6tlz2k1HZ91FNrzsZ
4VdiA/EzeN6BDDPTWuA13r7h8m0MntfaCTkNhjisDaAcMd/9sFZ3VVWfLw==
-----END PUBLIC KEY-----
`

			invalidCosignPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC0xfVLM3nSU6tlz2k1HZ91FNrzsZ
4VdiA/EzeN6BDDPTWuA13r7h8m0MntfaCTkNhjisDaAcMd/9sFZ3VVWfLw==
	-----END PUBLIC KEY-----
`
		)

		It("Should parse valid cosign public key", func() {
			keys, err := utils.GetCosignPublicKeys([]byte(validCosignPublicKey))
			Expect(err).ToNot(HaveOccurred())
			Expect(keys).ToNot(BeZero())
		})

		It("Should fail to parse invalid cosign public key", func() {
			keys, err := utils.GetCosignPublicKeys([]byte(invalidCosignPublicKey))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no valid keys were found"))
			Expect(keys).To(BeZero())
		})

		It("Should fail to parse invalid empty byte array", func() {
			keys, err := utils.GetCosignPublicKeys([]byte{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no valid keys were found"))
			Expect(keys).To(BeZero())
		})
	})

	Describe("lazyKeyChainReader", func() {
		It("Should run reader func only once", func() {
			counter := 0
			s := utils.NewLazyKeyChainReader(func() (authn.Keychain, error) {
				counter++
				return nil, nil
			})
			Expect(s).ToNot(BeNil())
			Expect(counter).To(BeNumerically("==", 0))
			kc, err := s.GetKeyChain()
			Expect(err).ToNot(HaveOccurred())
			Expect(kc).To(BeNil())
			Expect(counter).To(BeNumerically("==", 1))
			kc, err = s.GetKeyChain()
			Expect(err).ToNot(HaveOccurred())
			Expect(kc).To(BeNil())
			Expect(counter).To(BeNumerically("==", 1))
		})

		It("Should return expected error", func() {
			s := utils.NewLazyKeyChainReader(func() (kc authn.Keychain, err error) {
				return nil, fmt.Errorf("foo-bar")
			})
			Expect(s).ToNot(BeNil())

			kc, err := s.GetKeyChain()
			Expect(kc).To(BeNil())
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("foo-bar"))
		})

		It("Should return the expected key chain", func() {
			s := utils.NewLazyKeyChainReader(func() (authn.Keychain, error) {
				return authn.DefaultKeychain, nil
			})
			Expect(s).ToNot(BeNil())

			kc, err := s.GetKeyChain()
			Expect(err).ToNot(HaveOccurred())
			Expect(kc).ToNot(BeNil())
			Expect(kc).To(BeIdenticalTo(authn.DefaultKeychain))
		})
	})

})
