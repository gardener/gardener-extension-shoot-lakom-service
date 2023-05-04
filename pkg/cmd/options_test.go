// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd_test

import (
	"os"
	"path/filepath"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/cmd"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("options", func() {

	Describe("Complete", func() {

		It("Should fail when config path is not set", func() {
			svcOpt := cmd.LakomServiceOptions{}
			err := svcOpt.Complete()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("config location is not set"))
		})

		It("Should fail to decode invalid config", func() {
			var (
				invalidConfigContent = "foo"
			)

			configDir, err := os.MkdirTemp("", "invalid-lakom-config")
			Expect(err).To(Not(HaveOccurred()))
			defer func() {
				err := os.RemoveAll(configDir)
				Expect(err).To(Not((HaveOccurred())))
			}()

			configPath := filepath.Join(configDir, "config.yaml")
			err = os.WriteFile(configPath, []byte(invalidConfigContent), 0600)
			Expect(err).To(Not(HaveOccurred()))

			svcOpt := cmd.LakomServiceOptions{
				ConfigLocation: configPath,
			}
			err = svcOpt.Complete()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("json parse error: json: cannot unmarshal"))
		})

		It("Should successfully parse config", func() {
			var (
				configContent = `apiVersion: lakom.extensions.config.gardener.cloud/v1alpha1
kind: Configuration
healthCheckConfig:
  syncPeriod: 5m
`
			)

			configDir, err := os.MkdirTemp("", "lakom-config")
			Expect(err).To(Not(HaveOccurred()))
			defer func() {
				err := os.RemoveAll(configDir)
				Expect(err).To(Not((HaveOccurred())))
			}()

			configPath := filepath.Join(configDir, "config.yaml")
			err = os.WriteFile(configPath, []byte(configContent), 0600)
			Expect(err).To(Not(HaveOccurred()))

			svcOpt := cmd.LakomServiceOptions{
				ConfigLocation: configPath,
			}
			err = svcOpt.Complete()
			Expect(err).To(Not(HaveOccurred()))

			svcConfig := svcOpt.Completed()
			Expect(svcConfig).To(Not(BeNil()))
		})

	})

})
