// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd_test

import (
	"os"
	"path/filepath"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
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
			svcOpt, cleanupFunc := prepareServiceOptions("invalid-config")
			defer cleanupFunc()
			err := svcOpt.Complete()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("could not find expected ':'"))
		})

		It("Should successfully parse config", func() {
			svcOpt, cleanupFunc := prepareServiceOptions(`healthCheckConfig:
  syncPeriod: 5m`)
			defer cleanupFunc()
			err := svcOpt.Complete()
			Expect(err).To(Not(HaveOccurred()))

			svcConfig := svcOpt.Completed()
			Expect(svcConfig).To(Not(BeNil()))
		})
	})

	Describe("Validate", func() {
		DescribeTable("Should allow supported scopes", func(scope lakom.ScopeType) {
			svcOpt, cleanupFunc := prepareServiceOptions(`defaultLakomScope: ` + string(scope))
			defer cleanupFunc()
			Expect(svcOpt.Complete()).To(Succeed())
			Expect(svcOpt.Validate()).To(Succeed())

		},
			Entry("KubeSystem", lakom.KubeSystem),
			Entry("KubeSystemManagedByGardener", lakom.KubeSystemManagedByGardener),
			Entry("Cluster", lakom.Cluster),
		)

		It("Should allow empty scope", func() {
			svcOpt, cleanupFunc := prepareServiceOptions("")
			defer cleanupFunc()
			Expect(svcOpt.Complete()).To(Succeed())
			Expect(svcOpt.Validate()).To(Succeed())
		})

		It("Should disallow unsupported scope", func() {
			svcOpt, cleanupFunc := prepareServiceOptions("defaultLakomScope: unsupportedScope123")
			defer cleanupFunc()
			Expect(svcOpt.Complete()).To(Succeed())
			Expect(svcOpt.Validate()).To(And(
				HaveOccurred(),
				MatchError(ContainSubstring("unsupported defaultLakomScope")),
			))
		})
	})
})

func prepareServiceOptions(subconfig string) (cmd.LakomServiceOptions, func()) {
	var (
		configContent = `apiVersion: lakom.extensions.config.gardener.cloud/v1alpha1
kind: Configuration
` + subconfig
	)

	configDir, err := os.MkdirTemp("", "lakom-config")
	Expect(err).To(Not(HaveOccurred()))

	configPath := filepath.Join(configDir, "config.yaml")
	Expect(os.WriteFile(configPath, []byte(configContent), 0600)).To(Succeed())

	return cmd.LakomServiceOptions{ConfigLocation: configPath}, func() {
		Expect(os.RemoveAll(configDir)).To(Succeed())
	}
}
