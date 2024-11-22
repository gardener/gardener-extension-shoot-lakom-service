// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/yaml"
)

var _ = Describe("Complete Lakom Config", func() {

	Context("Duplicate keys are removed", func() {
		var (
			rawKeys = []byte(`- name: test-01
  algorithm: RSASSA-PKCS1-v1_5-SHA256
  key: |-
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5WIqxApep8Q53M5zrd0Hhuk03tCn
    On/cxJW6vXn3mvlqgyc4MO/ZXb5EputelfyP5n1NYWWcomeQTDG/E3EbdQ==
    -----END PUBLIC KEY-----
- name: test-02
  algorithm: RSASSA-PKCS1-v1_5-SHA256
  key: |-
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyLVOS/TWANf6sZJPDzogodvDz8NT
    hjZVcW2ygAvImCAULGph2fqGkNUszl7ycJH/Dntw4wMLSbstUZomqPuIVQ==
    -----END PUBLIC KEY-----
`)
			config     *Config
			parsedKeys []Key
		)
		err := yaml.Unmarshal(rawKeys, &parsedKeys)
		Expect(err).ToNot(HaveOccurred())

		BeforeEach(func() {
			config = &Config{}
		})

		It("should not remove keys if they are different", func() {
			config.PublicKeys = parsedKeys

			completedConfig, err := config.Complete()
			Expect(err).ToNot(HaveOccurred())

			Expect(len(completedConfig.Keys)).To(Equal(2))
		})

		It("should remove keys if there are duplicates", func() {
			config.PublicKeys = append(parsedKeys, parsedKeys[0])

			completedConfig, err := config.Complete()
			Expect(err).ToNot(HaveOccurred())

			Expect(len(completedConfig.Keys)).To(Equal(2))
		})

		It("should not remove keys if they are different but have the same name", func() {
			config.PublicKeys = parsedKeys
			config.PublicKeys[0].Name = config.PublicKeys[1].Name

			completedConfig, err := config.Complete()
			Expect(err).ToNot(HaveOccurred())

			Expect(len(completedConfig.Keys)).To(Equal(2))
		})

		It("should have no effect if there are no keys in the config", func() {
			config.PublicKeys = []Key{}

			completedConfig, err := config.Complete()
			Expect(err).ToNot(HaveOccurred())

			Expect(len(completedConfig.Keys)).To(Equal(0))
		})

	})
})
