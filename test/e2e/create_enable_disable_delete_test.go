// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"context"
	"time"

	e2e "github.com/gardener/gardener/test/e2e/gardener"
	tf "github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Lakom Extension Tests", Label("Lakom"), func() {
	f := defaultShootCreationFramework()
	f.Shoot = e2e.DefaultShoot("e2e-lakom-dis")

	It("Create Shoot, Enable and Disable Lakom Extension, Delete Shoot", Label("good-case"), func() {
		By("Create Shoot")
		ctx, cancel := context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.CreateShootAndWaitForCreation(ctx, false)).To(Succeed())
		f.Verify()

		By("Enable Lakom Extension")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.UpdateShoot(ctx, f.Shoot, ensureLakomServiceIsEnabled)).To(Succeed())

		_, seedClient, err := f.GetSeed(ctx, *f.Shoot.Status.SeedName)
		Expect(err).NotTo(HaveOccurred())
		project, err := f.GetShootProject(ctx, f.Shoot.Namespace)
		Expect(err).NotTo(HaveOccurred())
		shootSeedNamespace := tf.ComputeTechnicalID(project.Name, f.Shoot)

		By("Verify Lakom Deployment is running")
		depl, err := getLakomDeployment(ctx, seedClient.Client(), shootSeedNamespace)
		Expect(err).NotTo(HaveOccurred())
		one := int32(1)
		Expect(*depl.Spec.Replicas).To(BeNumerically(">=", one))
		Expect(depl.Status.ReadyReplicas).To(BeNumerically(">=", one))

		By("Disable Lakom Extension")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.UpdateShoot(ctx, f.Shoot, ensureLakomServiceIsDisabled)).To(Succeed())

		By("Verify Lakom resources are cleaned up")
		ensureLakomResourcesAreCleaned(ctx, seedClient.Client(), shootSeedNamespace)

		By("Delete Shoot")
		ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
		defer cancel()
		Expect(f.DeleteShootAndWaitForDeletion(ctx, f.Shoot)).To(Succeed())
	})
})
