// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package e2e_test

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/test/common"

	gardencorev1 "github.com/gardener/gardener/pkg/apis/core/v1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	seedmanagementv1alpha1 "github.com/gardener/gardener/pkg/apis/seedmanagement/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/gardener/operator"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	e2e "github.com/gardener/gardener/test/e2e"
	gardenere2e "github.com/gardener/gardener/test/e2e/gardener"
	gardenoperator "github.com/gardener/gardener/test/e2e/operator/garden"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const (
	// gardenRuntimeWorkloadNamespace is the namespace on the runtime cluster in which the signed/unsigned
	// workload pods are created. Must NOT be lakom-system/kube-system — the runtime webhook excludes those.
	gardenRuntimeWorkloadNamespace = "lakom-e2e-garden"

	// gardenTrustedKeysRefName is the NamedResourceReference name recorded in Garden.Spec.Resources and
	// referenced from the lakom providerConfig via trustedKeysResourceName.
	gardenTrustedKeysRefName = "lakom-e2e-garden-keys"
)

// gardenTrustedKeysSecretName is the actual Secret name the lakom garden actuator resolves the reference to.
// Gardener resolves NamedResourceReferences by prefixing the referenced object name with "ref-" (see
// extensions/pkg/controller.GetObjectByReference), and — unlike gardenlet for shoots — the operator does not
// copy Garden.Spec.Resources into "ref-"-prefixed objects. So the test must create the Secret already prefixed.
var gardenTrustedKeysSecretName = v1beta1constants.ReferencedResourcesPrefix + gardenTrustedKeysRefName

var _ = Describe("Lakom Extension Tests", Label("Lakom"), func() {
	Context("Garden signature verification", Label("garden-signature-verification"), Ordered, func() {
		var (
			gardenContext *gardenere2e.GardenContext

			privateKey       *ecdsa.PrivateKey
			publicKeyPEM     string
			signedImageRef   string
			unsignedImageRef string
		)

		// Attach to existing garden "local"
		e2e.BeforeTestSetup(func() {
			garden := &operatorv1alpha1.Garden{
				ObjectMeta: metav1.ObjectMeta{
					Name: "local",
				},
			}
			gardenContext = gardenere2e.NewTestContext().ForGarden(garden, nil)
		})

		BeforeAll(func(ctx SpecContext) {
			By("Generate cosing key pair")
			var err error
			privateKey, publicKeyPEM, err = common.GenerateKeyPair()
			Expect(err).ToNot(HaveOccurred())

			By("Push+sign a trusted image, push an untrusted image")
			signedImage, signedRef, err := common.PushRandomImage(fmt.Sprintf("%s/lakom-e2e-garden-signed", localRegistry))
			Expect(err).ToNot(HaveOccurred())
			Expect(common.SignImage(signedImage, signedRef, privateKey)).To(Succeed())
			signedImageRef = signedRef

			_, unsignedRef, err := common.PushRandomImage(fmt.Sprintf("%s/lakom-e2e-garden-unsigned", localRegistry))
			Expect(err).ToNot(HaveOccurred())
			unsignedImageRef = unsignedRef

			// The following two steps set up state shared by all specs in this Ordered container: the
			// trusted-keys Secret and the enabled lakom garden extension. They live in BeforeAll (not in
			// individual It nodes) so that the DeferCleanups registered here are scoped to the whole
			// container and run once after the last spec (LIFO) — a DeferCleanup registered inside an It
			// in an Ordered container would instead run right after that It, tearing the extension down
			// before the later specs could observe the deployed workload.

			By("Fetch the local Garden and create the trusted-keys Secret")
			Expect(gardenContext.GardenClient.Get(ctx, client.ObjectKeyFromObject(gardenContext.Garden), gardenContext.Garden)).To(Succeed())

			keysSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      gardenTrustedKeysSecretName,
					Namespace: v1beta1constants.GardenNamespace, // "garden"
				},
				StringData: map[string]string{
					"keys": fmt.Sprintf("- name: lakom-e2e-garden-key\n  key: |-\n%s", indent(publicKeyPEM, "    ")),
				},
			}
			Expect(gardenContext.GardenClient.Create(ctx, keysSecret)).To(Or(Succeed(), BeAlreadyExistsError()))
			DeferCleanup(func(ctx SpecContext) {
				Expect(gardenContext.GardenClient.Delete(ctx, keysSecret)).To(Or(Succeed(), BeNotFoundError()))
			})

			By("Sign the lakom extension image so its garden-virtual pods pass the runtime signature webhook")
			// The garden-runtime verify-signature webhook validates every pod created outside
			// lakom-system/kube-system, including the garden-VIRTUAL lakom flavour that runs in namespace
			// "garden". With the local skaffold dev image (unsigned) lakom would reject the creation of its
			// own garden-virtual pods. Signing that image with the same trusted key BEFORE the extension is
			// enabled means those pods are admitted on their very first creation — no ReplicaFailure, no
			// create-backoff, no rollout restart. The image ref is read from the skaffold-generated operator
			// imagevector overwrite, which is already on disk before this test runs.
			lakomImageRef, err := lakomImageRefFromImageVectorOverwrite()
			Expect(err).ToNot(HaveOccurred())
			Expect(common.SignImageByRef(lakomImageRef, privateKey)).To(Succeed())

			By("Enable the lakom garden extension with a trusted key")
			patch := client.MergeFrom(gardenContext.Garden.DeepCopy())
			common.AddOrUpdateGardenResourceReference(gardenContext.Garden, gardenTrustedKeysRefName, "Secret", gardenTrustedKeysRefName)
			common.AddOrUpdateGardenLakomExtensionWithTrustedKeys(gardenContext.Garden, gardenTrustedKeysRefName)
			Expect(gardenContext.GardenClient.Patch(ctx, gardenContext.Garden, patch)).To(Succeed())

			DeferCleanup(func(ctx SpecContext) {
				Expect(gardenContext.GardenClient.Get(ctx, client.ObjectKeyFromObject(gardenContext.Garden), gardenContext.Garden)).To(Succeed())
				p := client.MergeFrom(gardenContext.Garden.DeepCopy())
				common.RemoveGardenLakomExtension(gardenContext.Garden)
				common.RemoveGardenResourceReference(gardenContext.Garden, gardenTrustedKeysRefName)
				Expect(gardenContext.GardenClient.Patch(ctx, gardenContext.Garden, p)).To(Succeed())

				Eventually(ctx, func(g Gomega) {
					err := gardenContext.GardenClient.Get(ctx, client.ObjectKey{
						Namespace: constants.LakomSystemNamespaceName,
						Name:      constants.GardenRuntimeExtensionServiceName,
					}, &appsv1.Deployment{})
					g.Expect(err).To(BeNotFoundError())
				}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
			})
		}, NodeTimeout(5*time.Minute))

		It("Wait for the garden-runtime deployment and runtime webhook", func(ctx SpecContext) {
			// Enabling the extension re-triggers a Garden reconciliation. The operator's extension
			// controller only deploys the garden-runtime workload once the Garden reports
			// "Reconcile Succeeded" (see IsGardenSuccessfullyReconciled), so wait for that first —
			// otherwise the runtime Deployment simply never appears within a short window. The Garden
			// reconcile can take several minutes, matching gardener's own ItShouldWaitForGardenToBeReconciledAndHealthy.
			Eventually(ctx, func(g Gomega) {
				g.Expect(gardenContext.GardenClient.Get(ctx, client.ObjectKeyFromObject(gardenContext.Garden), gardenContext.Garden)).To(Succeed())
				g.Expect(operator.IsGardenSuccessfullyReconciled(gardenContext.Garden)).To(BeTrue(), "Garden is not yet successfully reconciled")
			}).WithTimeout(15 * time.Minute).WithPolling(10 * time.Second).Should(Succeed())

			Eventually(ctx, func(g Gomega) {
				deploy := &appsv1.Deployment{}
				g.Expect(gardenContext.GardenClient.Get(ctx, client.ObjectKey{
					Namespace: constants.LakomSystemNamespaceName,
					Name:      constants.GardenRuntimeExtensionServiceName,
				}, deploy)).To(Succeed())
				g.Expect(deploy.Status.ReadyReplicas).To(BeNumerically(">=", 1))

				g.Expect(gardenContext.GardenClient.Get(ctx,
					client.ObjectKey{Name: constants.GardenRuntimeWebhookConfigurationName},
					&admissionregistrationv1.ValidatingWebhookConfiguration{})).To(Succeed())
			}).WithTimeout(5 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		}, SpecTimeout(21*time.Minute))

		// gardenContext.VirtualClusterClient from the "gardener" secret in ns "garden" on the runtime cluster.
		gardenoperator.ItShouldInitializeVirtualClusterClient(gardenContext)

		It("Ensure the virtual-garden webhook exists and its backend is ready", func(ctx SpecContext) {
			// The virtual webhook config existing is not enough to invoke it: the garden-virtual
			// flavour runs its own Deployment (ns "garden", useInClusterAuth:false — it authenticates
			// to the virtual-garden apiserver via an injected generic kubeconfig / shoot-access token)
			// with a ReadinessProbe. Until those pods are Ready the Service has no endpoints and the
			// webhook URL (https://...garden-virtual.garden/...) has no backend, so a ControllerDeployment
			// admission call times out with "context deadline exceeded". Wait for the backend here so the
			// later virtual-webhook spec exercises a live path (mirrors the garden-runtime wait above).
			Eventually(ctx, func(g Gomega) {
				g.Expect(gardenContext.VirtualClusterClient.Get(ctx,
					client.ObjectKey{Name: constants.GardenVirtualWebhookConfigurationName},
					&admissionregistrationv1.ValidatingWebhookConfiguration{})).To(Succeed())

				deploy := &appsv1.Deployment{}
				g.Expect(gardenContext.GardenClient.Get(ctx, client.ObjectKey{
					Namespace: v1beta1constants.GardenNamespace,
					Name:      constants.GardenVirtualExtensionServiceName,
				}, deploy)).To(Succeed())
				g.Expect(deploy.Status.ReadyReplicas).To(BeNumerically(">=", 1))
			}).WithTimeout(8 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		}, SpecTimeout(9*time.Minute))

		It("Admit a signed pod and reject an unsigned pod (runtime webhook)", func(ctx SpecContext) {
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: gardenRuntimeWorkloadNamespace}}
			Expect(gardenContext.GardenClient.Create(ctx, ns)).To(Or(Succeed(), BeAlreadyExistsError()))
			DeferCleanup(func(ctx SpecContext) {
				Expect(gardenContext.GardenClient.Delete(ctx, ns)).To(Or(Succeed(), BeNotFoundError()))
			})

			signed := buildPodInNamespace("garden-signed", signedImageRef, gardenRuntimeWorkloadNamespace)
			Expect(gardenContext.GardenClient.Create(ctx, signed)).To(Succeed())
			DeferCleanup(func(ctx SpecContext) {
				Expect(gardenContext.GardenClient.Delete(ctx, signed)).To(Or(Succeed(), BeNotFoundError()))
			})

			unsigned := buildPodInNamespace("garden-unsigned", unsignedImageRef, gardenRuntimeWorkloadNamespace)
			err := gardenContext.GardenClient.Create(ctx, unsigned)
			Expect(err).To(BeForbiddenError())
			Expect(err.Error()).To(ContainSubstring("verify-signature.lakom.service.extensions.gardener.cloud"))
		}, SpecTimeout(3*time.Minute))

		It("Admit a signed Extension and reject an unsigned Extension (runtime webhook)", func(ctx SpecContext) {
			// Besides Pods, the garden-runtime webhook also validates operator.gardener.cloud/v1alpha1
			// Extensions, extracting the OCI ref from spec.deployment.extension.helm.ociRepository. Both
			// creates use dry-run: lakom's webhook has sideEffects=None so it is still invoked on dry-run,
			// but nothing is persisted — so gardener-operator never starts reconciling these throwaway
			// Extensions (which reference random test artifacts, not real charts). The runtime registry
			// connection and signature cache are already warm from the pod spec above.
			signedExt := buildExtension("lakom-e2e-garden-ext-signed-", signedImageRef)
			Expect(gardenContext.GardenClient.Create(ctx, signedExt, client.DryRunAll)).To(Succeed())

			unsignedExt := buildExtension("lakom-e2e-garden-ext-unsigned-", unsignedImageRef)
			err := gardenContext.GardenClient.Create(ctx, unsignedExt, client.DryRunAll)
			Expect(err).To(BeForbiddenError())
			Expect(err.Error()).To(ContainSubstring("verify-signature.lakom.service.extensions.gardener.cloud"))
			Expect(err.Error()).To(ContainSubstring("no valid signature found"))
		}, SpecTimeout(3*time.Minute))

		It("Reject an unsigned ControllerDeployment (virtual webhook)", func(ctx SpecContext) {
			// Positive control: a signed CD must be admitted (proves the webhook inspects the field and
			// does not blanket-deny). The garden-virtual lakom pod has only just become Ready, and its
			// very first verification reaches out to the local registry to fetch the artifact + signature.
			// That first, cold connection can exceed the webhook's request context deadline, surfacing as
			// an "Internal error: ... Get https://registry.local.gardener.cloud:5001/v2/: context canceled"
			// 403 — a transient infrastructure hiccup, NOT a signature rejection. Retry until the signed CD
			// is admitted; this also warms the registry connection before the negative assertion below.
			Eventually(ctx, func(g Gomega) {
				signedCD := buildControllerDeployment("lakom-e2e-garden-signed-", signedImageRef)
				g.Expect(gardenContext.VirtualClusterClient.Create(ctx, signedCD)).To(Succeed())
				// Clean up the successfully-admitted CD; only reached once Create succeeded.
				g.Expect(gardenContext.VirtualClusterClient.Delete(ctx, signedCD)).To(Or(Succeed(), BeNotFoundError()))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())

			// Negative: an unsigned CD must be rejected by the signature-verification webhook. Use Eventually
			// as well so a transient registry error (context canceled) does not masquerade as the wrong
			// failure — retry until the rejection is specifically the lakom verify-signature denial.
			Eventually(ctx, func(g Gomega) {
				unsignedCD := buildControllerDeployment("lakom-e2e-garden-unsigned-", unsignedImageRef)
				err := gardenContext.VirtualClusterClient.Create(ctx, unsignedCD)
				g.Expect(err).To(BeForbiddenError())
				g.Expect(err.Error()).To(ContainSubstring("verify-signature.lakom.service.extensions.gardener.cloud"))
				g.Expect(err.Error()).To(ContainSubstring("no valid signature found"))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		}, SpecTimeout(5*time.Minute))

		It("Admit a signed Gardenlet and reject an unsigned Gardenlet (virtual webhook)", func(ctx SpecContext) {
			// Besides ControllerDeployments, the garden-virtual webhook also validates
			// seedmanagement.gardener.cloud/v1alpha1 Gardenlets, extracting the OCI ref from
			// spec.deployment.helm.ociRepository. As with the ControllerDeployment above, the first
			// verification can hit a transient registry error, so retry with Eventually. Both creates use
			// dry-run (lakom sideEffects=None → still invoked, nothing persisted) so gardener never deploys a
			// throwaway gardenlet from these random test artifacts.
			Eventually(ctx, func(g Gomega) {
				signedGardenlet := buildGardenlet("lakom-e2e-garden-gardenlet-signed-", signedImageRef)
				g.Expect(gardenContext.VirtualClusterClient.Create(ctx, signedGardenlet, client.DryRunAll)).To(Succeed())
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())

			Eventually(ctx, func(g Gomega) {
				unsignedGardenlet := buildGardenlet("lakom-e2e-garden-gardenlet-unsigned-", unsignedImageRef)
				err := gardenContext.VirtualClusterClient.Create(ctx, unsignedGardenlet, client.DryRunAll)
				g.Expect(err).To(BeForbiddenError())
				g.Expect(err.Error()).To(ContainSubstring("verify-signature.lakom.service.extensions.gardener.cloud"))
				g.Expect(err.Error()).To(ContainSubstring("no valid signature found"))
			}).WithTimeout(2 * time.Minute).WithPolling(5 * time.Second).Should(Succeed())
		}, SpecTimeout(5*time.Minute))
	})
})

// buildPodInNamespace mirrors buildPod but takes an explicit namespace (runtime cluster).
func buildPodInNamespace(name, imageRef, namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
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

// buildControllerDeployment returns a minimal ControllerDeployment whose helm chart OCI ref is imageRef —
// the field the lakom garden-virtual webhook extracts and verifies (helm.ociRepository). If Helm/OCIRepository
// were nil the webhook would produce no verification targets and admit unconditionally, so the ref must be set.
func buildControllerDeployment(generateName, imageRef string) *gardencorev1.ControllerDeployment {
	return &gardencorev1.ControllerDeployment{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Helm: &gardencorev1.HelmControllerDeployment{
			OCIRepository: &gardencorev1.OCIRepository{Ref: &imageRef},
		},
	}
}

// buildExtension returns a minimal, schema-valid operator Extension (cluster-scoped) whose extension helm
// chart OCI ref is imageRef. That is the field the lakom garden-runtime webhook extracts and verifies
// (spec.deployment.extension.helm.ociRepository); every other field is optional per the operator's Extension
// validation, so this is the smallest object that still exercises signature verification.
func buildExtension(generateName, imageRef string) *operatorv1alpha1.Extension {
	return &operatorv1alpha1.Extension{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName},
		Spec: operatorv1alpha1.ExtensionSpec{
			Deployment: &operatorv1alpha1.Deployment{
				ExtensionDeployment: &operatorv1alpha1.ExtensionDeploymentSpec{
					DeploymentSpec: operatorv1alpha1.DeploymentSpec{
						Helm: &operatorv1alpha1.ExtensionHelm{
							OCIRepository: &gardencorev1.OCIRepository{Ref: &imageRef},
						},
					},
				},
			},
		},
	}
}

// buildGardenlet returns a minimal, schema-valid Gardenlet whose deployment helm chart OCI ref is imageRef —
// the field the lakom garden-virtual webhook extracts and verifies (spec.deployment.helm.ociRepository).
// seedmanagement validation only requires a valid OCIRepository ref, a DNS-label name and namespace "garden"
// (spec.config is optional and omitted), so this is the smallest object that still exercises verification.
func buildGardenlet(generateName, imageRef string) *seedmanagementv1alpha1.Gardenlet {
	return &seedmanagementv1alpha1.Gardenlet{
		ObjectMeta: metav1.ObjectMeta{GenerateName: generateName, Namespace: v1beta1constants.GardenNamespace},
		Spec: seedmanagementv1alpha1.GardenletSpec{
			Deployment: seedmanagementv1alpha1.GardenletSelfDeployment{
				Helm: seedmanagementv1alpha1.GardenletHelm{
					OCIRepository: gardencorev1.OCIRepository{Ref: &imageRef},
				},
			},
		},
	}
}

// skaffold wrote into the operator imagevector overwrite during "extension-operator-e2e-up". This is the
// exact image the operator deploys for both lakom flavours, so signing it before the extension is enabled
// lets the garden-virtual lakom pods pass the runtime signature webhook on their first creation.
func lakomImageRefFromImageVectorOverwrite() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("could not determine caller to locate the imagevector overwrite file")
	}
	// <repo>/test/e2e/create_enable_verify_signature_garden_test.go -> <repo>
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "local-setup", "operator", "patch-imagevector-overwrite.yaml")

	// #nosec G304 -- path is derived solely from runtime.Caller and fixed path segments (no external input); it always points at the in-repo imagevector overwrite.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read imagevector overwrite %s: %w", path, err)
	}

	var overwrite struct {
		Spec struct {
			Deployment struct {
				Extension struct {
					Values struct {
						ImageVectorOverwrite struct {
							Images []struct {
								Name       string `json:"name"`
								Repository string `json:"repository"`
								Tag        string `json:"tag"`
							} `json:"images"`
						} `json:"imageVectorOverwrite"`
					} `json:"values"`
				} `json:"extension"`
			} `json:"deployment"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &overwrite); err != nil {
		return "", fmt.Errorf("failed to parse imagevector overwrite %s: %w", path, err)
	}

	for _, img := range overwrite.Spec.Deployment.Extension.Values.ImageVectorOverwrite.Images {
		if img.Name == "lakom" && img.Repository != "" && img.Tag != "" {
			return fmt.Sprintf("%s:%s", img.Repository, img.Tag), nil
		}
	}
	return "", fmt.Errorf("no lakom image with repository and tag found in %s", path)
}
