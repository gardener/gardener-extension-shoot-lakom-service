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
			config     *Config
			parsedKeys []Key
		)

		BeforeEach(func() {
			rawKeys := []byte(`- name: test-01-ecdsa-key
  algorithm: RSASSA-PKCS1-v1_5-SHA256
  key: |-
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5WIqxApep8Q53M5zrd0Hhuk03tCn
    On/cxJW6vXn3mvlqgyc4MO/ZXb5EputelfyP5n1NYWWcomeQTDG/E3EbdQ==
    -----END PUBLIC KEY-----
- name: test-02-rsa-key
  algorithm: RSASSA-PSS-SHA512
  key: |-
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr/yPqOYHsJlqI1cj5TH+
    BDeRrcwFFb1gHe3BMSrTeMSFEwNcJN6agdzN4OPBhbDkpsL/WRZjsQoVh3IcWgHy
    rj8WgkukNuWrQIRzpY7NnDlVuL5IhrQxRxepDFOZB6AHr/QiE4xlKULa3820CQ2v
    Fm3xiZEfElDrva0/0kbxVISMJ8VSeTmUf5XyYJ0PiKZ9/gyYTqi11NI2HTCYAb0h
    5VX7TLEEGajRM6IYbfXt0Plw8ygYW5L1ze3DWUCd0qlIT27rrLeLIy1MNU1ExrJF
    2IFIJ81kzOZRG107AXTP3Ms0+Agy+3/5joM/HmS0CH0HEHiFp+ZE856Sw5Mnlnac
    JwIDAQAB
    -----END PUBLIC KEY-----
`)
			Expect(yaml.Unmarshal(rawKeys, &parsedKeys)).To(Succeed())
			Expect(parsedKeys).To(HaveLen(2))

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

		It("should not remove keys if they are the same but have different hash function", func() {
			config.PublicKeys = append(parsedKeys, parsedKeys[1])
			Expect(config.PublicKeys).To(HaveLen(3))

			config.PublicKeys[1].Algorithm = RSASSAPSSSHA512
			config.PublicKeys[2].Algorithm = RSASSAPSSSHA384

			completedConfig, err := config.Complete()
			Expect(err).ToNot(HaveOccurred())

			Expect(len(completedConfig.Keys)).To(Equal(3))
		})

		It("should not remove keys if they are the same but have different RSA schemes", func() {
			config.PublicKeys = append(parsedKeys, parsedKeys[1])
			Expect(config.PublicKeys).To(HaveLen(3))

			config.PublicKeys[1].Algorithm = RSAPKCS1v15SHA384
			config.PublicKeys[2].Algorithm = RSASSAPSSSHA384

			completedConfig, err := config.Complete()
			Expect(err).ToNot(HaveOccurred())

			Expect(len(completedConfig.Keys)).To(Equal(3))
		})

		It("should have no effect if there are no keys in the config", func() {
			config.PublicKeys = []Key{}

			completedConfig, err := config.Complete()
			Expect(err).ToNot(HaveOccurred())

			Expect(len(completedConfig.Keys)).To(Equal(0))
		})

	})
})
