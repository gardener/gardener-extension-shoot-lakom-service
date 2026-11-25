// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/test/common"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/controllerutils"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	e2e "github.com/gardener/gardener/test/e2e"
	gardenere2e "github.com/gardener/gardener/test/e2e/gardener"
	gardenerseed "github.com/gardener/gardener/test/e2e/gardener/seed"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// seedWorkloadNamespace is the namespace on the seed cluster in which the signed/unsigned workload pods
	// are created. It must NOT be kube-system - the seed webhook excludes it.
	seedWorkloadNamespace = "lakom-e2e-seed"

	// seedTrustedKeysRefName is the NamedResourceReference name recorded in Seed.Spec.Resources and referenced
	// from the lakom providerConfig via trustedKeysResourceName.
	seedTrustedKeysRefName = "lakom-e2e-seed-keys"

	// localSeedName is the name of the seed registered by the gardenlet in the local gardener landscape.
	localSeedName = "local"
)

// seedTrustedKeysSecretName is the name under which the trusted-keys Secret is created in the garden cluster's
// "garden" namespace. Unlike the garden extension (where the operator does not copy Garden.Spec.Resources, so the
// test must pre-create a "ref-"-prefixed Secret), for a seed-class extension gardenlet copies the referenced
// Secret into the seed's "garden" namespace with a "ref-" prefix. So here the source Secret is created with the
// UNprefixed ref name, and gardenlet adds the prefix when copying it to the seed.
const seedTrustedKeysSecretName = seedTrustedKeysRefName

var _ = Describe("Lakom Extension Tests", Label("Lakom"), func() {
	Context("Seed signature verification", Label("seed-signature-verification"), Ordered, func() {
		var (
			seedContext *gardenere2e.SeedContext

			privateKey       *ecdsa.PrivateKey
			publicKeyPEM     string
			signedImageRef   string
			unsignedImageRef string

			keysSecret *corev1.Secret
		)

		// Attach to the existing seed "local".
		e2e.BeforeTestSetup(func() {
			seed := &gardencorev1beta1.Seed{
				ObjectMeta: metav1.ObjectMeta{
					Name: localSeedName,
				},
			}
			seedContext = gardenere2e.NewTestContext().ForSeed(seed)
		})

		BeforeAll(func(ctx SpecContext) {
			By("Generate cosign key pair")
			var err error
			privateKey, publicKeyPEM, err = common.GenerateKeyPair()
			Expect(err).ToNot(HaveOccurred())

			By("Push+sign a trusted image, push an untrusted image")
			signedImage, signedRef, err := common.PushRandomImage(fmt.Sprintf("%s/lakom-e2e-seed-signed", localRegistry))
			Expect(err).ToNot(HaveOccurred())
			Expect(common.SignImage(signedImage, signedRef, privateKey)).To(Succeed())
			signedImageRef = signedRef

			_, unsignedRef, err := common.PushRandomImage(fmt.Sprintf("%s/lakom-e2e-seed-unsigned", localRegistry))
			Expect(err).ToNot(HaveOccurred())
			unsignedImageRef = unsignedRef

			// The following two steps set up state shared by all specs in this Ordered container: the
			// trusted-keys Secret and the enabled lakom seed extension. They live in BeforeAll (not in
			// individual It nodes) so that the DeferCleanups registered here are scoped to the whole container
			// and run once after the last spec (LIFO) — a DeferCleanup registered inside an It in an Ordered
			// container would instead run right after that It, tearing the extension down before the later
			// specs could observe the deployed workload.

			By("Fetch the local Seed and create the trusted-keys Secret in the garden cluster")
			Expect(seedContext.GardenClient.Get(ctx, client.ObjectKeyFromObject(seedContext.Seed), seedContext.Seed)).To(Succeed())

			keysSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					// UNprefixed name — gardenlet adds the "ref-" prefix when copying the Secret into the seed.
					Name:      seedTrustedKeysSecretName,
					Namespace: v1beta1constants.GardenNamespace, // "garden"
				},
			}
			// Use GetAndCreateOrMergePatch so a Secret left over from a previous run (possibly carrying a
			// different key) is updated to the key generated above, rather than kept stale.
			_, err = controllerutils.GetAndCreateOrMergePatch(ctx, seedContext.GardenClient, keysSecret, func() error {
				keysSecret.StringData = map[string]string{
					"keys": fmt.Sprintf("- name: lakom-e2e-seed-key\n  key: |-\n%s", indent(publicKeyPEM, "    ")),
				}
				return nil
			})
			Expect(err).ToNot(HaveOccurred())
			DeferCleanup(func(ctx SpecContext) {
				Expect(seedContext.GardenClient.Delete(ctx, keysSecret)).To(Or(Succeed(), BeNotFoundError()))
			})

			By("Enable the lakom seed extension with a trusted key")
			patch := client.MergeFrom(seedContext.Seed.DeepCopy())
			// resourceName is the UNprefixed ref name: gardenlet copies the referenced Secret into the seed's
			// "garden" namespace with a "ref-" prefix, and the lakom actuator re-adds the "ref-" prefix when
			// resolving the reference. keysSecret is passed only so Kind/APIVersion are derived from the real
			// object via the scheme.
			Expect(common.AddOrUpdateSeedResourceReference(seedContext.Seed, seedTrustedKeysRefName, keysSecret, seedTrustedKeysRefName, seedContext.GardenClient.Scheme())).To(Succeed())
			Expect(common.AddOrUpdateSeedLakomExtensionWithTrustedKeys(seedContext.Seed, seedTrustedKeysRefName)).To(Succeed())
			Expect(seedContext.GardenClient.Patch(ctx, seedContext.Seed, patch)).To(Succeed())

			DeferCleanup(func(ctx SpecContext) {
				Expect(seedContext.GardenClient.Get(ctx, client.ObjectKeyFromObject(seedContext.Seed), seedContext.Seed)).To(Succeed())
				p := client.MergeFrom(seedContext.Seed.DeepCopy())
				common.RemoveSeedLakomExtension(seedContext.Seed)
				common.RemoveSeedResourceReference(seedContext.Seed, seedTrustedKeysRefName)
				Expect(seedContext.GardenClient.Patch(ctx, seedContext.Seed, p)).To(Succeed())

				Eventually(ctx, func(g Gomega) {
					err := seedContext.SeedClient.Get(ctx, client.ObjectKey{
						Namespace: metav1.NamespaceSystem,
						Name:      constants.SeedExtensionServiceName,
					}, &appsv1.Deployment{})
					g.Expect(err).To(BeNotFoundError())
				}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
			})
		}, NodeTimeout(5*time.Minute))

		// Initialize the seed client from the "seed-local" kubeconfig Secret in the garden cluster's "garden"
		// namespace. Registers its own It node and must run before any spec touching seedContext.SeedClient.
		gardenerseed.ItShouldInitializeSeedClient(seedContext)

		// Enabling the extension changed Seed.Spec, which triggers a gardenlet reconcile. Force the reconcile
		// explicitly and wait for the Seed to become ready before asserting on the deployed workload, reusing
		// gardener's own helpers rather than a hand-rolled wait. Each registers its own It node.
		gardenerseed.ItShouldAnnotateSeed(seedContext, map[string]string{
			v1beta1constants.GardenerOperation: v1beta1constants.GardenerOperationReconcile,
		})
		gardenerseed.ItShouldWaitForSeedToBeReady(seedContext)

		It("Wait for the seed lakom deployment and seed webhook", func(ctx SpecContext) {
			Eventually(ctx, func(g Gomega) {
				deploy := &appsv1.Deployment{}
				g.Expect(seedContext.SeedClient.Get(ctx, client.ObjectKey{
					Namespace: metav1.NamespaceSystem,
					Name:      constants.SeedExtensionServiceName,
				}, deploy)).To(Succeed())
				g.Expect(deploy.Status.ReadyReplicas).To(BeNumerically(">=", 1))

				g.Expect(seedContext.SeedClient.Get(ctx,
					client.ObjectKey{Name: constants.SeedWebhookConfigurationName},
					&admissionregistrationv1.ValidatingWebhookConfiguration{})).To(Succeed())
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		}, SpecTimeout(6*time.Minute))

		It("Admit a signed pod and reject an unsigned pod (seed webhook)", func(ctx SpecContext) {
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: seedWorkloadNamespace}}
			Expect(seedContext.SeedClient.Create(ctx, ns)).To(Or(Succeed(), BeAlreadyExistsError()))
			DeferCleanup(func(ctx SpecContext) {
				Expect(seedContext.SeedClient.Delete(ctx, ns)).To(Or(Succeed(), BeNotFoundError()))
			})

			// Retry the signed pod with Eventually: the lakom seed pod has just become Ready and its first
			// verification makes a cold registry connection that can transiently time out. Creating (and
			// deleting) the signed pod first also warms that connection and the signature cache before the
			// negative assertion below.
			Eventually(ctx, func(g Gomega) {
				signed := buildPodInNamespace("seed-signed", signedImageRef, seedWorkloadNamespace)
				g.Expect(seedContext.SeedClient.Create(ctx, signed)).To(Succeed())
				g.Expect(seedContext.SeedClient.Delete(ctx, signed)).To(Or(Succeed(), BeNotFoundError()))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())

			unsigned := buildPodInNamespace("seed-unsigned", unsignedImageRef, seedWorkloadNamespace)
			err := seedContext.SeedClient.Create(ctx, unsigned)
			Expect(err).To(BeForbiddenError())
			Expect(err.Error()).To(ContainSubstring("verify-signature.lakom.service.extensions.gardener.cloud"))
		}, SpecTimeout(5*time.Minute))
	})
})
