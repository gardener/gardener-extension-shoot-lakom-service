// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"time"

	apislakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	"github.com/gardener/gardener-extension-shoot-lakom-service/test/common"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	e2e "github.com/gardener/gardener/test/e2e/gardener"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// localRegistry is the in-cluster registry of the local (kind-based) Gardener landscape. The test runner
	// pushes images here and the lakom webhook (running on the seed) fetches manifests from the same address.
	localRegistry = "registry.local.gardener.cloud:5001"

	// verifyTestNamespace is the shoot namespace in which the signed/unsigned workload pods are created.
	// With scope: Cluster lakom guards all namespaces, so a dedicated namespace keeps the test isolated
	// from system workloads.
	verifyTestNamespace = "lakom-e2e"

	// trustedKeysResourceRefName is the name of the shoot resource reference pointing to the Secret that
	// carries the additional trusted cosign public key.
	trustedKeysResourceRefName = "lakom-e2e-keys"
)

var _ = Describe("Lakom Extension Tests", Label("Lakom"), func() {
	Context("Signature verification", Label("signature-verification"), Ordered, func() {
		var (
			f = defaultShootCreationFrameworkWithShootAccess()

			privateKey       *ecdsa.PrivateKey
			publicKeyPEM     string
			signedImageRef   string
			unsignedImageRef string
		)

		f.Shoot = e2e.DefaultShoot("e2e-lakom-sig")

		BeforeAll(func() {
			By("Generate cosign key pair")
			var err error
			privateKey, publicKeyPEM, err = common.GenerateKeyPair()
			Expect(err).ToNot(HaveOccurred())

			By("Push and sign a trusted image, push an untrusted image")
			signedImage, signedRef, err := common.PushRandomImage(fmt.Sprintf("%s/lakom-e2e-signed", localRegistry))
			Expect(err).ToNot(HaveOccurred())
			Expect(common.SignImage(signedImage, signedRef, privateKey)).To(Succeed())
			signedImageRef = signedRef

			_, unsignedRef, err := common.PushRandomImage(fmt.Sprintf("%s/lakom-e2e-unsigned", localRegistry))
			Expect(err).ToNot(HaveOccurred())
			unsignedImageRef = unsignedRef
		})

		It("Create Shoot, enable Lakom with a trusted key, admit signed and reject unsigned images, delete Shoot", Label("good-case"), func() {
			By("Create Shoot")
			ctx, cancel := context.WithTimeout(parentCtx, 15*time.Minute)
			DeferCleanup(cancel)
			Expect(f.CreateShootAndWaitForCreation(ctx, false)).To(Succeed())
			f.Verify()

			// Register cleanups before creating resources so they also run on the failure path.
			// LIFO order yields: in-shoot pod -> namespace -> Shoot -> trusted-keys Secret.
			// The Secret must be deleted last: the lakom validator rejects Shoot deletion while the
			// referenced Secret is missing (see pkg/admission/validator/lakom/shoot.go validateTrustedKeys).
			// In-shoot resources must go first, before the Shoot's API server.
			var keysSecret *corev1.Secret
			DeferCleanup(func() {
				if keysSecret == nil {
					return
				}
				ctx, cancel := context.WithTimeout(parentCtx, 1*time.Minute)
				defer cancel()
				Expect(f.GardenClient.Client().Delete(ctx, keysSecret)).To(Or(Succeed(), BeNotFoundError()))
			})
			DeferCleanup(func() {
				ctx, cancel := context.WithTimeout(parentCtx, 15*time.Minute)
				defer cancel()
				Expect(f.DeleteShootAndWaitForDeletion(ctx, f.Shoot)).To(Succeed())
			})

			By("Create Secret with the trusted cosign public key")
			ctx, cancel = context.WithTimeout(parentCtx, 1*time.Minute)
			DeferCleanup(cancel)
			keysSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "lakom-e2e-keys-",
					Namespace:    f.ProjectNamespace,
				},
				StringData: map[string]string{
					"keys": fmt.Sprintf("- name: lakom-e2e-key\n  key: |-\n%s", indent(publicKeyPEM, "    ")),
				},
			}
			Expect(f.GardenClient.Client().Create(ctx, keysSecret)).To(Succeed())

			By("Enable Lakom Extension with scope Cluster and the trusted key reference")
			ctx, cancel = context.WithTimeout(parentCtx, 15*time.Minute)
			DeferCleanup(cancel)
			Expect(f.UpdateShoot(ctx, f.Shoot, func(shoot *gardencorev1beta1.Shoot) error {
				common.AddOrUpdateShootResourceReference(shoot, trustedKeysResourceRefName, "Secret", keysSecret.Name)
				common.AddOrUpdateShootLakomExtensionWithTrustedKeys(shoot, apislakom.Cluster, trustedKeysResourceRefName)
				return nil
			})).To(Succeed())

			shootClient := f.ShootFramework.ShootClient.Client()

			By("Create the workload namespace in the Shoot")
			ctx, cancel = context.WithTimeout(parentCtx, 1*time.Minute)
			DeferCleanup(cancel)
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: verifyTestNamespace}}
			Expect(shootClient.Create(ctx, ns)).To(Or(Succeed(), BeAlreadyExistsError()))
			DeferCleanup(func() {
				ctx, cancel := context.WithTimeout(parentCtx, 2*time.Minute)
				defer cancel()
				Expect(shootClient.Delete(ctx, ns)).To(Or(Succeed(), BeNotFoundError()))
			})

			By("Assert the signed image is admitted by the Lakom webhook")
			ctx, cancel = context.WithTimeout(parentCtx, 2*time.Minute)
			DeferCleanup(cancel)
			signedPod := buildPod("signed-test", signedImageRef)
			Expect(shootClient.Create(ctx, signedPod)).To(Succeed())
			DeferCleanup(func() {
				ctx, cancel := context.WithTimeout(parentCtx, 1*time.Minute)
				defer cancel()
				Expect(shootClient.Delete(ctx, signedPod)).To(Or(Succeed(), BeNotFoundError()))
			})

			By("Assert the unsigned image is rejected by the Lakom webhook")
			unsignedPod := buildPod("unsigned-test", unsignedImageRef)
			err := shootClient.Create(ctx, unsignedPod)
			Expect(err).To(BeForbiddenError())
			Expect(err.Error()).To(ContainSubstring("verify-signature.lakom.service.extensions.gardener.cloud"))
		})
	})
})

// buildPod returns a Pod definition in the verify test namespace referencing the given image by digest.
// The image is a randomly-generated OCI artifact that cannot actually start; the test only asserts on the
// admission decision (Create succeeds or is denied), not on the Pod reaching a running state. Therefore the
// image is never pulled by a node and imagePullPolicy is set to Never.
func buildPod(name, imageRef string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: verifyTestNamespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:            "test",
				Image:           imageRef,
				ImagePullPolicy: corev1.PullNever,
			}},
		},
	}
}

// indent prefixes every line of s with the given prefix.
func indent(s, prefix string) string {
	var b []byte
	lineStart := true
	for i := 0; i < len(s); i++ {
		if lineStart {
			b = append(b, prefix...)
			lineStart = false
		}
		b = append(b, s[i])
		if s[i] == '\n' {
			lineStart = true
		}
	}
	return string(b)
}
