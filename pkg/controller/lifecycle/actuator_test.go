// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	b64 "encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Actuator", func() {

	DescribeTable("Should get correct number of replicas",
		func(hibernated bool) {
			expectedReplicas := 3
			if hibernated {
				expectedReplicas = 0
			}

			actual := getLakomReplicas(hibernated)
			Expect(*actual).To(BeEquivalentTo(expectedReplicas))
		},
		Entry("Awaken", false),
		Entry("Hibernated", true),
	)

	It("Should get labels", func() {
		labels := getLabels()

		Expect(labels).To(HaveLen(2))
		appName, appNameOK := labels["app.kubernetes.io/name"]
		Expect(appNameOK).To(BeTrue())
		Expect(appName).To(Equal("lakom"))

		appPartOf, appPartOfOK := labels["app.kubernetes.io/part-of"]
		Expect(appPartOfOK).To(BeTrue())
		Expect(appPartOf).To(Equal("shoot-lakom-service"))
	})

	DescribeTable("Should get the garden pod labels with a variant-specific instance label",
		func(virtualGarden bool, expectedInstance string) {
			labels := getGardenPodLabels(virtualGarden)

			// The common labels must always be present ...
			Expect(labels).To(HaveKeyWithValue("app.kubernetes.io/name", "lakom"))
			Expect(labels).To(HaveKeyWithValue("app.kubernetes.io/part-of", "shoot-lakom-service"))
			// ... plus the variant-specific instance label used to give the runtime and
			// virtual garden deployments disjoint selectors.
			Expect(labels).To(HaveKeyWithValue("app.kubernetes.io/instance", expectedInstance))
			Expect(labels).To(HaveLen(3))
		},
		Entry("Runtime garden variant", false, constants.GardenRuntimeExtensionServiceName),
		Entry("Virtual garden variant", true, constants.GardenVirtualExtensionServiceName),
	)

	It("Should give the runtime and virtual garden variants disjoint selectors", func() {
		Expect(getGardenPodLabels(false)).ToNot(Equal(getGardenPodLabels(true)))
	})

	DescribeTable("Should get the expected scope", func(configurableScope lakom.ScopeType, expected string) {
		Expect(getScope(lakom.ScopeType(configurableScope))).To(BeEquivalentTo(&expected))
	},
		Entry("Global default scope: KubeSystemManagedByGardener", lakom.ScopeType(""), "KubeSystemManagedByGardener"),
		Entry("Overwrite scope: Cluster", lakom.Cluster, "Cluster"),
		Entry("Overwrite scope: KubeSystem", lakom.KubeSystem, "KubeSystem"),
		Entry("Overwrite scope: KubeSystemManagedByGardener", lakom.KubeSystemManagedByGardener, "KubeSystemManagedByGardener"),
	)

	DescribeTable("Should get correct (cluster)rolebindings", func(scope lakom.ScopeType, dashboardEnabled bool, expectCRB bool, expectedBindingsCount int) {
		bindings := getRoleBindings(scope, "sa-name", dashboardEnabled)
		Expect(bindings).To(HaveLen(expectedBindingsCount))
		if expectCRB {
			Expect(bindings[0]).To(BeAssignableToTypeOf(&rbacv1.ClusterRoleBinding{}))
		} else {
			Expect(bindings[0]).To(BeAssignableToTypeOf(&rbacv1.RoleBinding{}))
			Expect(bindings[0].GetNamespace()).To(Equal("kube-system"))

			if expectedBindingsCount == 2 {
				Expect(bindings[1]).To(BeAssignableToTypeOf(&rbacv1.RoleBinding{}))
				Expect(bindings[1].GetNamespace()).To(Equal("kubernetes-dashboard"))
			}
		}
	},
		Entry("One ClusterRoleBinding only when scope is Cluster (dashboard disabled)", lakom.Cluster, false, true, 1),
		Entry("One ClusterRoleBinding only when scope is Cluster (dashboard enabled)", lakom.Cluster, true, true, 1),
		Entry("One RoleBinding when scope is KubeSystem (dashboard disabled)", lakom.KubeSystem, false, false, 1),
		Entry("Two RoleBindings when scope is KubeSystem (dashboard enabled)", lakom.KubeSystem, true, false, 2),
		Entry("One RoleBinding when scope is KubeSystemManagedByGardener (dashboard disabled)", lakom.KubeSystemManagedByGardener, false, false, 1),
		Entry("Two RoleBindings when scope is KubeSystemManagedByGardener (dashboard enabled)", lakom.KubeSystemManagedByGardener, true, false, 2),
	)

	Context("getWebhookResources", func() {
		const (
			shootNamespace                  = "garden-foo"
			extensionNamespace              = "shoot--foo--bar"
			scope                           = lakom.KubeSystemManagedByGardener
			dashboardEnabled                = false
			shootAccessServiceAccountName   = "extension-shoot-lakom-service-access"
			managedByGardenerObjectSelector = `
    matchExpressions:
    - key: resources.gardener.cloud/managed-by
      operator: In
      values:
      - gardener`
			emptyObjectSelector         = ` {}`
			kubeSystemNamespaceSelector = `
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: In
      values:
      - kube-system`
			kubeSystemAndDashboardNamespaceSelector = `
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: In
      values:
      - kube-system
      - kubernetes-dashboard`
			emptyNamespaceSelector = ` {}`
		)
		var (
			caBundle = []byte("caBundle")
		)

		It("Should ensure the correct shoot resources are created", func() {

			resources, err := getWebhookResources(shootWebhookVariant(constants.WebhookConfigurationName, shootAccessServiceAccountName, scope, false), caBundle, shootWebhookRules, constants.ExtensionServiceName, extensionNamespace)
			Expect(err).ToNot(HaveOccurred())
			manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
			Expect(err).ToNot(HaveOccurred())

			Expect(manifests).To(ConsistOf(
				expectedSeedValidatingWebhook(caBundle, extensionNamespace, managedByGardenerObjectSelector, kubeSystemNamespaceSelector),
				expectedShootMutatingWebhook(caBundle, extensionNamespace, managedByGardenerObjectSelector, kubeSystemNamespaceSelector),
				expectedShootClusterRole(),
				expectedShootRoleBinding(shootAccessServiceAccountName, scope, "kube-system"),
			))

			By("Enable kubernetes dashboard addon")
			resources, err = getWebhookResources(shootWebhookVariant(constants.WebhookConfigurationName, shootAccessServiceAccountName, scope, true), caBundle, shootWebhookRules, constants.ExtensionServiceName, extensionNamespace)
			Expect(err).ToNot(HaveOccurred())
			manifests, err = test.ExtractManifestsFromManagedResourceData(resources)
			Expect(err).ToNot(HaveOccurred())

			Expect(manifests).To(ConsistOf(
				expectedSeedValidatingWebhook(caBundle, extensionNamespace, managedByGardenerObjectSelector, kubeSystemAndDashboardNamespaceSelector),
				expectedShootMutatingWebhook(caBundle, extensionNamespace, managedByGardenerObjectSelector, kubeSystemAndDashboardNamespaceSelector),
				expectedShootClusterRole(),
				expectedShootRoleBinding(shootAccessServiceAccountName, scope, "kube-system"),
				expectedShootRoleBinding(shootAccessServiceAccountName, scope, "kubernetes-dashboard"),
			))
		})

		DescribeTable("Should ensure the mutating webhook config is correctly set",
			func(ca []byte, ns string) {
				resources, err := getWebhookResources(shootWebhookVariant(constants.WebhookConfigurationName, shootAccessServiceAccountName, scope, dashboardEnabled), ca, shootWebhookRules, constants.ExtensionServiceName, ns)
				Expect(err).ToNot(HaveOccurred())
				manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
				Expect(err).ToNot(HaveOccurred())

				Expect(manifests).To(ContainElement(expectedShootMutatingWebhook(ca, ns, managedByGardenerObjectSelector, kubeSystemNamespaceSelector)))
			},
			Entry("Global CA bundle and namespace name", caBundle, extensionNamespace),
			Entry("Custom CA bundle and namespace name", []byte("anotherCABundle"), "different-namespace"),
		)

		DescribeTable("Should ensure the validating webhook config is correctly set",
			func(ca []byte, ns string) {
				resources, err := getWebhookResources(shootWebhookVariant(constants.WebhookConfigurationName, shootAccessServiceAccountName, scope, dashboardEnabled), ca, shootWebhookRules, constants.ExtensionServiceName, ns)
				Expect(err).ToNot(HaveOccurred())
				manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
				Expect(err).ToNot(HaveOccurred())

				Expect(manifests).To(ContainElement(expectedSeedValidatingWebhook(ca, ns, managedByGardenerObjectSelector, kubeSystemNamespaceSelector)))
			},
			Entry("Global CA bundle and namespace name", caBundle, extensionNamespace),
			Entry("Custom CA bundle and namespace name", []byte("anotherCABundle"), "different-namespace"),
		)

		DescribeTable("Should return an empty object selector for the webhooks when scope is KubeSystem",
			func(ca []byte, ns string) {
				resources, err := getWebhookResources(shootWebhookVariant(constants.WebhookConfigurationName, shootAccessServiceAccountName, lakom.KubeSystem, dashboardEnabled), ca, shootWebhookRules, constants.ExtensionServiceName, ns)
				Expect(err).ToNot(HaveOccurred())
				manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
				Expect(err).ToNot(HaveOccurred())

				Expect(manifests).To(ContainElements(
					expectedShootMutatingWebhook(ca, ns, emptyObjectSelector, kubeSystemNamespaceSelector),
					expectedSeedValidatingWebhook(ca, ns, emptyObjectSelector, kubeSystemNamespaceSelector),
				))
			},
			Entry("Global CA bundle and namespace name", caBundle, extensionNamespace),
			Entry("Custom CA bundle and namespace name", []byte("anotherCABundle"), "different-namespace"),
		)

		DescribeTable("Should ensure the rolebinding is correctly set",
			func(saName string, lakomScope lakom.ScopeType, bindingNamespace string) {
				resources, err := getWebhookResources(shootWebhookVariant(constants.WebhookConfigurationName, saName, lakomScope, dashboardEnabled), caBundle, shootWebhookRules, constants.ExtensionServiceName, extensionNamespace)
				Expect(err).ToNot(HaveOccurred())
				manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
				Expect(err).ToNot(HaveOccurred())

				Expect(manifests).To(ContainElement(expectedShootRoleBinding(saName, lakomScope, bindingNamespace)))
			},
			Entry("ServiceAccount name: test, scope: KubeSystemManagedByGardener", "test", lakom.KubeSystemManagedByGardener, "kube-system"),
			Entry("ServiceAccount name: foo-bar, scope: KubeSystem", "foo-bar", lakom.KubeSystem, "kube-system"),
			Entry("ServiceAccount name: foo-bar, scope: Cluster", "foo-bar", lakom.Cluster, ""),
		)

		DescribeTable("Should return the correct object and namespace selectors based on scope",
			func(scope lakom.ScopeType, objectSelector, namespaceSelector string) {
				resources, err := getWebhookResources(shootWebhookVariant(constants.WebhookConfigurationName, shootAccessServiceAccountName, scope, dashboardEnabled), caBundle, shootWebhookRules, constants.ExtensionServiceName, extensionNamespace)
				Expect(err).ToNot(HaveOccurred())
				manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
				Expect(err).ToNot(HaveOccurred())

				Expect(manifests).To(ContainElements(
					expectedShootMutatingWebhook(caBundle, extensionNamespace, objectSelector, namespaceSelector),
					expectedSeedValidatingWebhook(caBundle, extensionNamespace, objectSelector, namespaceSelector),
				))
			},
			Entry("KubeSystemManagedByGardener scope", lakom.KubeSystemManagedByGardener, managedByGardenerObjectSelector, kubeSystemNamespaceSelector),
			Entry("KubeSystem scope", lakom.KubeSystem, emptyObjectSelector, kubeSystemNamespaceSelector),
			Entry("Cluster scope", lakom.Cluster, emptyObjectSelector, emptyNamespaceSelector),
		)

	})

	Context("webhookVariant constructors", func() {
		It("Should build a shoot webhook variant that is URL-based and carries a resource-reader ServiceAccount", func() {
			v := shootWebhookVariant(constants.WebhookConfigurationName, "some-sa", lakom.KubeSystemManagedByGardener, false)

			Expect(v.configName).To(Equal(constants.WebhookConfigurationName))
			Expect(v.resourceReaderSA).To(Equal("some-sa"))
			Expect(v.useServiceClientConfig).To(BeFalse())
			Expect(v.registry).ToNot(BeNil())
		})

		It("Should build a runtime webhook variant that is Service-based and has no resource-reader ServiceAccount", func() {
			v := gardenRuntimeWebhookVariant()

			Expect(v.configName).To(Equal(constants.GardenRuntimeWebhookConfigurationName))
			// The runtime lakom runs in the same (runtime) cluster it validates, so it is reached
			// via a Service reference rather than a URL, and it reads secrets in-cluster instead of
			// through a shoot-access ServiceAccount.
			Expect(v.resourceReaderSA).To(BeEmpty())
			Expect(v.useServiceClientConfig).To(BeTrue())
			Expect(v.registry).ToNot(BeNil())
			// The runtime webhook must exclude Lakom's own to prevent self-deadlock in virtual-garden
			Expect(v.objectSelector.MatchExpressions).To(ContainElement(metav1.LabelSelectorRequirement{
				Key:      "app.kubernetes.io/part-of",
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{constants.ExtensionType},
			}))
		})
	})

	Context("getWebhookResources for the garden extension class", func() {
		var (
			caBundle = []byte("caBundle")
		)

		It("Should create Service-based runtime garden webhook configs without any RBAC resources", func() {
			resources, err := getWebhookResources(
				gardenRuntimeWebhookVariant(),
				caBundle,
				gardenWebhookRuntimeRules,
				constants.GardenRuntimeExtensionServiceName,
				constants.LakomSystemNamespace,
			)
			Expect(err).ToNot(HaveOccurred())
			manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
			Expect(err).ToNot(HaveOccurred())

			// The runtime variant has no resourceReaderSA, so only the two webhook configs are
			// rendered - no ClusterRole and no (Cluster)RoleBinding.
			Expect(manifests).To(ConsistOf(
				expectedRuntimeGardenMutatingWebhook(caBundle),
				expectedRuntimeGardenValidatingWebhook(caBundle),
			))
		})

		It("Should create URL-based virtual garden webhook configs targeting the virtual garden resources", func() {
			resources, err := getWebhookResources(
				gardenVirtualWebhookVariant("gardenAccessSA"),
				caBundle,
				gardenWebhookVirtualGardenRules,
				constants.GardenVirtualExtensionServiceName,
				"garden",
			)
			Expect(err).ToNot(HaveOccurred())
			manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
			Expect(err).ToNot(HaveOccurred())

			Expect(manifests).To(ContainElements(
				expectedVirtualGardenMutatingWebhook(caBundle, "garden"),
				expectedVirtualGardenValidatingWebhook(caBundle, "garden"),
			))
		})
	})

	Context("getClientKeys", func() {
		const (
			resourceName             = "trusted-keys"
			resourceNoKeysName       = resourceName + "-no-keys"
			secretName               = "lakom-secret"
			prefixedSecretName       = v1beta1constants.ReferencedResourcesPrefix + secretName
			secretNoKeysName         = secretName + "-no-keys"
			prefixedSecretNoKeysName = v1beta1constants.ReferencedResourcesPrefix + secretNoKeysName
			namespace                = "shoot--local--local"
		)
		var (
			ctx        = context.TODO()
			fakeclient = fakeclient.NewFakeClient()
			secretData = []byte(`- name: test-01
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
			resources    []gardencorev1beta1.NamedResourceReference
			data         map[string][]byte
			dataNoKeys   map[string][]byte
			secret       *corev1.Secret
			secretNoKeys *corev1.Secret
		)

		BeforeEach(func() {
			resources = []gardencorev1beta1.NamedResourceReference{
				{
					Name: resourceName,
					ResourceRef: autoscalingv1.CrossVersionObjectReference{
						Kind:       "Secret",
						Name:       secretName,
						APIVersion: "v1",
					},
				},
				{
					Name: resourceNoKeysName,
					ResourceRef: autoscalingv1.CrossVersionObjectReference{
						Kind:       "Secret",
						Name:       secretNoKeysName,
						APIVersion: "v1",
					},
				},
			}

		})

		data = make(map[string][]byte)
		dataNoKeys = make(map[string][]byte)
		data["keys"] = secretData
		// When resources are registered in the shoot spec,
		// they get copied by Gardener to the shoot namespace but
		// prefixed with some string to avoid collisions.
		// v1beta1constants.ReferencedResourcePrefix is the aforementioned prefix.
		//
		// More info can be found here: https://github.com/gardener/gardener/blob/master/docs/extensions/referenced-resources.md
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      prefixedSecretName,
				Namespace: namespace,
			},
			Data: data,
		}
		secretNoKeys = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      prefixedSecretNoKeysName,
				Namespace: namespace,
			},
			Data: dataNoKeys,
		}

		Expect(fakeclient.Create(ctx, secret)).ToNot(HaveOccurred())
		Expect(fakeclient.Create(ctx, secretNoKeys)).ToNot(HaveOccurred())

		It("Should return the secret when the resource is correct", func() {
			result, err := getClientKeys(ctx, fakeclient, resources, resourceName, namespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(secretData))
		})

		It("Should return an err if the resource is not found", func() {
			_, err := getClientKeys(ctx, fakeclient, resources[0:0], resourceName, namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to find referenced resource with name " + resourceName))
		})

		It("Should return an err if the reference is found but the resource with the given name is not found", func() {
			wrongName := "non-existent"
			prefixedWrongName := v1beta1constants.ReferencedResourcesPrefix + wrongName
			resources[0].ResourceRef.Name = "non-existent"

			_, err := getClientKeys(ctx, fakeclient, resources, resourceName, namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to read referenced secret " + prefixedWrongName + " for reference " + resourceName))
		})

		It("Should return an err if the reference is found, but its kind is not 'Secret'", func() {
			resources[0].ResourceRef.Kind = "ConfigMap"

			_, err := getClientKeys(ctx, fakeclient, resources, resourceName, namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("references resource with name " + resourceName + " is not of kind 'Secret'"))
		})

		It("Should return an err if the Secret does not contains a 'keys' key in its data", func() {
			_, err := getClientKeys(ctx, fakeclient, resources, resourceNoKeysName, namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("secret " + namespace + "/" + prefixedSecretNoKeysName + " is missing data key 'keys'"))
		})
	})

	Context("getSeedResources", func() {
		const (
			namespace                     = "shoot--for--bar"
			genericKubeconfigName         = "generic-kubeconfig"
			shootAccessServiceAccountName = "extension-shoot-lakom-service"
			serverTLSSecretName           = "shoot-lakom-service-tls" //#nosec G101 -- this is false positive
			image                         = "europe-docker.pkg.dev/gardener-project/releases/gardener/extensions/lakom:v0.0.0"
			lakomConfigConfigMapName      = "extension-shoot-lakom-service-lakom-config-5ccba116"
		)

		var (
			replicas    int32
			lakomConfig string
		)

		BeforeEach(func() {
			replicas = int32(3)

			lakomConfig = `publicKeys:
- name: test-01
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
`
		})

		DescribeTable("Should ensure resources are correctly created",
			func(useOnlyImagePullSecrets, allowUntrustedImages, allowInsecureRegistries bool) {
				resources, err := getSeedResources(
					&replicas,
					constants.ExtensionServiceName,
					namespace,
					genericKubeconfigName,
					shootAccessServiceAccountName,
					serverTLSSecretName,
					lakomConfig,
					image,
					useOnlyImagePullSecrets,
					allowUntrustedImages,
					allowInsecureRegistries,
					true,
					"v1.34.0",
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(resources).To(HaveKey("data.yaml.br"))
				compressedData := resources["data.yaml.br"]
				data, err := test.BrotliDecompression(compressedData)
				Expect(err).NotTo(HaveOccurred())

				manifests := strings.Split(string(data), "\n---\n") // Just '---\n' does not work because of the header/footer in the public keys that match the same manifest separator
				Expect(manifests).To(HaveLen(7))

				for i := range manifests { // Re-add the trailing '\n' removed during the split from the separator above
					if i < len(manifests)-1 {
						manifests[i] += "\n"
					}
				}

				Expect(manifests).To(ConsistOf(
					expectedSeedDeployment(replicas, namespace, genericKubeconfigName, shootAccessServiceAccountName, image, lakomConfigConfigMapName, serverTLSSecretName, strconv.FormatBool(useOnlyImagePullSecrets), strconv.FormatBool(allowUntrustedImages), strconv.FormatBool(allowInsecureRegistries)),
					expectedSeedPDB(namespace),
					expectedSeedConfigMapLakomConfig(namespace, lakomConfigConfigMapName, lakomConfig),
					expectedSeedService(namespace),
					expectedSeedServiceAccount(namespace, shootAccessServiceAccountName),
					expectedSeedVPA(namespace),
					expectedSeedServiceMonitor(namespace),
				))
			},
			Entry("Default config", false, false, false),
			Entry("Use only image pull secrets", true, false, false),
			Entry("Allow untrusted images", false, true, false),
			Entry("Allow insecure registries", false, false, true),
		)
	})

	Context("getGardenVirtualResources", func() {
		const (
			namespace                = "garden"
			genericKubeconfigName    = "generic-kubeconfig"
			gardenAccessSecretName   = "garden-access-sa"
			serverTLSSecretName      = "shoot-lakom-service-tls" //#nosec G101 -- this is false positive
			image                    = "europe-docker.pkg.dev/gardener-project/releases/gardener/extensions/lakom:v0.0.0"
			lakomConfigConfigMapName = "extension-shoot-lakom-service-garden-virtual-lakom-config-5ccba116"
		)

		var (
			replicas    int32
			lakomConfig string
		)

		BeforeEach(func() {
			replicas = int32(3)

			lakomConfig = `publicKeys:
- name: test-01
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
`
		})

		DescribeTable("Should ensure resources are correctly created",
			func(useOnlyImagePullSecrets, allowUntrustedImages, allowInsecureRegistries bool) {
				resources, err := getGardenVirtualResources(
					&replicas,
					namespace,
					genericKubeconfigName,
					gardenAccessSecretName,
					serverTLSSecretName,
					lakomConfig,
					image,
					useOnlyImagePullSecrets,
					allowUntrustedImages,
					allowInsecureRegistries,
					true,
					"v1.34.0",
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(resources).To(HaveKey("data.yaml.br"))
				compressedData := resources["data.yaml.br"]
				data, err := test.BrotliDecompression(compressedData)
				Expect(err).NotTo(HaveOccurred())

				manifests := strings.Split(string(data), "\n---\n") // Just '---\n' does not work because of the header/footer in the public keys that match the same manifest separator
				Expect(manifests).To(HaveLen(7))

				for i := range manifests { // Re-add the trailing '\n' removed during the split from the separator above
					if i < len(manifests)-1 {
						manifests[i] += "\n"
					}
				}

				Expect(manifests).To(ConsistOf(
					expectedGardenVirtualDeployment(replicas, namespace, genericKubeconfigName, gardenAccessSecretName, image, lakomConfigConfigMapName, serverTLSSecretName, strconv.FormatBool(useOnlyImagePullSecrets), strconv.FormatBool(allowUntrustedImages), strconv.FormatBool(allowInsecureRegistries)),
					expectedGardenVirtualPDB(namespace),
					expectedSeedConfigMapLakomConfig(namespace, lakomConfigConfigMapName, lakomConfig),
					expectedGardenVirtualService(namespace),
					expectedGardenVirtualServiceAccount(namespace),
					expectedGardenVirtualVPA(namespace),
					expectedGardenVirtualServiceMonitor(namespace),
				))
			},
			Entry("Default config", false, false, false),
			Entry("Use only image pull secrets", true, false, false),
			Entry("Allow untrusted images", false, true, false),
			Entry("Allow insecure registries", false, false, true),
		)
	})

	Context("getGardenRuntimeResources", func() {
		const (
			namespace                = "lakom-system"
			serverTLSSecretName      = "shoot-lakom-service-tls" //#nosec G101 -- this is false positive
			image                    = "europe-docker.pkg.dev/gardener-project/releases/gardener/extensions/lakom:v0.0.0"
			lakomConfigConfigMapName = "extension-shoot-lakom-service-garden-runtime-lakom-config-5ccba116"
		)

		var (
			replicas    int32
			lakomConfig string
		)

		BeforeEach(func() {
			replicas = int32(3)

			lakomConfig = `publicKeys:
- name: test-01
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
`
		})

		DescribeTable("Should ensure resources are correctly created",
			func(useOnlyImagePullSecrets, allowUntrustedImages, allowInsecureRegistries bool) {
				serverTLSSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: serverTLSSecretName},
					Type:       corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"tls.crt": []byte("test-cert"),
						"tls.key": []byte("test-key"),
					},
				}
				resources, err := getGardenRuntimeResources(
					&replicas,
					serverTLSSecret,
					lakomConfig,
					image,
					useOnlyImagePullSecrets,
					allowUntrustedImages,
					allowInsecureRegistries,
					true,
					"v1.34.0",
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(resources).To(HaveKey("data.yaml.br"))
				compressedData := resources["data.yaml.br"]
				data, err := test.BrotliDecompression(compressedData)
				Expect(err).NotTo(HaveOccurred())

				manifests := strings.Split(string(data), "\n---\n") // Just '---\n' does not work because of the header/footer in the public keys that match the same manifest separator
				Expect(manifests).To(HaveLen(11))

				for i := range manifests { // Re-add the trailing '\n' removed during the split from the separator above
					if i < len(manifests)-1 {
						manifests[i] += "\n"
					}
				}

				Expect(manifests).To(ConsistOf(
					expectedGardenRuntimeDeployment(replicas, namespace, image, lakomConfigConfigMapName, serverTLSSecretName, strconv.FormatBool(useOnlyImagePullSecrets), strconv.FormatBool(allowUntrustedImages), strconv.FormatBool(allowInsecureRegistries)),
					expectedGardenRuntimeNamespace(namespace),
					expectedGardenRuntimeTLSSecret(namespace, serverTLSSecretName),
					expectedGardenRuntimePDB(namespace),
					expectedSeedConfigMapLakomConfig(namespace, lakomConfigConfigMapName, lakomConfig),
					expectedGardenRuntimeService(namespace),
					expectedGardenRuntimeServiceAccount(namespace),
					expectedGardenRuntimeRole(namespace),
					expectedGardenRuntimeRoleBinding(namespace),
					expectedGardenRuntimeVPA(namespace),
					expectedGardenRuntimeServiceMonitor(namespace),
				))
			},
			Entry("Default config", false, false, false),
			Entry("Use only image pull secrets", true, false, false),
			Entry("Allow untrusted images", false, true, false),
			Entry("Allow insecure registries", false, false, true),
		)
	})
})

func expectedShootMutatingWebhook(caBundle []byte, namespace string, objectSelector string, namespaceSelector string) string {
	caBundleEncoded := b64.StdEncoding.EncodeToString(caBundle)

	return `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: gardener-extension-shoot-lakom-service-shoot
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ` + caBundleEncoded + `
    url: https://extension-shoot-lakom-service.` + namespace + `/lakom/resolve-tag-to-digest
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: resolve-tag.lakom.service.extensions.gardener.cloud
  namespaceSelector:` + namespaceSelector + `
  objectSelector:` + objectSelector + `
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - pods
    - pods/ephemeralcontainers
  sideEffects: None
  timeoutSeconds: 25
`
}

func expectedSeedValidatingWebhook(caBundle []byte, namespace string, objectSelector string, namespaceSelector string) string {
	caBundleEncoded := b64.StdEncoding.EncodeToString(caBundle)

	return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: gardener-extension-shoot-lakom-service-shoot
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ` + caBundleEncoded + `
    url: https://extension-shoot-lakom-service.` + namespace + `/lakom/verify-cosign-signature
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: verify-signature.lakom.service.extensions.gardener.cloud
  namespaceSelector:` + namespaceSelector + `
  objectSelector:` + objectSelector + `
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - pods
    - pods/ephemeralcontainers
  sideEffects: None
  timeoutSeconds: 25
`
}

func expectedRuntimeGardenMutatingWebhook(caBundle []byte) string {
	caBundleEncoded := b64.StdEncoding.EncodeToString(caBundle)

	return `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: gardener-extension-shoot-lakom-service-runtime-garden
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ` + caBundleEncoded + `
    service:
      name: extension-shoot-lakom-service-garden-runtime
      namespace: lakom-system
      path: /lakom/resolve-tag-to-digest
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: resolve-tag.lakom.service.extensions.gardener.cloud
  namespaceSelector:
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values:
      - lakom-system
  objectSelector:
    matchExpressions:
    - key: app.kubernetes.io/part-of
      operator: NotIn
      values:
      - shoot-lakom-service
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - pods
    - pods/ephemeralcontainers
  - apiGroups:
    - operator.gardener.cloud
    apiVersions:
    - v1alpha1
    operations:
    - CREATE
    - UPDATE
    resources:
    - extensions
  sideEffects: None
  timeoutSeconds: 25
`
}

func expectedRuntimeGardenValidatingWebhook(caBundle []byte) string {
	caBundleEncoded := b64.StdEncoding.EncodeToString(caBundle)

	return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: gardener-extension-shoot-lakom-service-runtime-garden
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ` + caBundleEncoded + `
    service:
      name: extension-shoot-lakom-service-garden-runtime
      namespace: lakom-system
      path: /lakom/verify-cosign-signature
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: verify-signature.lakom.service.extensions.gardener.cloud
  namespaceSelector:
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values:
      - lakom-system
  objectSelector:
    matchExpressions:
    - key: app.kubernetes.io/part-of
      operator: NotIn
      values:
      - shoot-lakom-service
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - pods
    - pods/ephemeralcontainers
  - apiGroups:
    - operator.gardener.cloud
    apiVersions:
    - v1alpha1
    operations:
    - CREATE
    - UPDATE
    resources:
    - extensions
  sideEffects: None
  timeoutSeconds: 25
`
}

func expectedVirtualGardenMutatingWebhook(caBundle []byte, namespace string) string {
	caBundleEncoded := b64.StdEncoding.EncodeToString(caBundle)

	return `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: gardener-extension-shoot-lakom-service-virtual-garden
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ` + caBundleEncoded + `
    url: https://extension-shoot-lakom-service-garden-virtual.` + namespace + `/lakom/resolve-tag-to-digest
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: resolve-tag.lakom.service.extensions.gardener.cloud
  namespaceSelector: {}
  objectSelector: {}
  rules:
  - apiGroups:
    - core.gardener.cloud
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - controllerdeployments
  - apiGroups:
    - seedmanagement.gardener.cloud
    apiVersions:
    - v1alpha1
    operations:
    - CREATE
    - UPDATE
    resources:
    - gardenlets
  sideEffects: None
  timeoutSeconds: 25
`
}

func expectedVirtualGardenValidatingWebhook(caBundle []byte, namespace string) string {
	caBundleEncoded := b64.StdEncoding.EncodeToString(caBundle)

	return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: gardener-extension-shoot-lakom-service-virtual-garden
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ` + caBundleEncoded + `
    url: https://extension-shoot-lakom-service-garden-virtual.` + namespace + `/lakom/verify-cosign-signature
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: verify-signature.lakom.service.extensions.gardener.cloud
  namespaceSelector: {}
  objectSelector: {}
  rules:
  - apiGroups:
    - core.gardener.cloud
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - controllerdeployments
  - apiGroups:
    - seedmanagement.gardener.cloud
    apiVersions:
    - v1alpha1
    operations:
    - CREATE
    - UPDATE
    resources:
    - gardenlets
  sideEffects: None
  timeoutSeconds: 25
`
}

func expectedShootClusterRole() string {
	return `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: gardener-extension-shoot-lakom-service-resource-reader
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
`
}

func expectedShootRoleBinding(saName string, lakomScope lakom.ScopeType, namespace string) string {
	if lakomScope == lakom.Cluster {
		return `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    resources.gardener.cloud/delete-on-invalid-update: "true"
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: gardener-extension-shoot-lakom-service-resource-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: gardener-extension-shoot-lakom-service-resource-reader
subjects:
- kind: ServiceAccount
  name: ` + saName + `
  namespace: kube-system
`
	}

	return `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  annotations:
    resources.gardener.cloud/delete-on-invalid-update: "true"
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: gardener-extension-shoot-lakom-service-resource-reader
  namespace: ` + namespace + `
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: gardener-extension-shoot-lakom-service-resource-reader
subjects:
- kind: ServiceAccount
  name: ` + saName + `
  namespace: kube-system
`
}

func expectedSeedServiceMonitor(namespace string) string {
	return `apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    prometheus: shoot
  name: shoot-extension-shoot-lakom-service
  namespace: ` + namespace + `
spec:
  endpoints:
  - metricRelabelings:
    - action: keep
      regex: ^(lakom_.*|controller_runtime_webhook_.*)$
      sourceLabels:
      - __name__
    port: metrics
  namespaceSelector: {}
  selector:
    matchLabels:
      app.kubernetes.io/name: lakom
      app.kubernetes.io/part-of: shoot-lakom-service
`
}

func expectedSeedDeployment(replicas int32, namespace, genericKubeconfigSecretName, shootAccessSecretName, image, lakomConfigConfigMapName, serverTLSSecretName, useOnlyImagePullSecrets, allowUntrustedImages, allowInsecureRegistries string) string {
	var (
		genericKubeconfigSecretNameAnnotationKey = references.AnnotationKey("secret", genericKubeconfigSecretName)
		shootAccessSecretNameAnnotationKey       = references.AnnotationKey("secret", shootAccessSecretName)
		serverTLSSecretNameAnnotationKey         = references.AnnotationKey("secret", serverTLSSecretName)
		lakomConfigConfigMapNameAnnotationKey    = references.AnnotationKey("configmap", lakomConfigConfigMapName)

		annotations = []string{
			lakomConfigConfigMapNameAnnotationKey + ": " + lakomConfigConfigMapName,
			genericKubeconfigSecretNameAnnotationKey + ": " + genericKubeconfigSecretName,
			shootAccessSecretNameAnnotationKey + ": " + shootAccessSecretName,
			serverTLSSecretNameAnnotationKey + ": " + serverTLSSecretName,
		}
	)

	return `apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    ` + strings.Join(annotations, "\n    ") + `
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    high-availability-config.resources.gardener.cloud/type: server
  name: extension-shoot-lakom-service
  namespace: ` + namespace + `
spec:
  replicas: ` + fmt.Sprintf("%d", replicas) + `
  revisionHistoryLimit: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: lakom
      app.kubernetes.io/part-of: shoot-lakom-service
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
    type: RollingUpdate
  template:
    metadata:
      annotations:
        ` + strings.Join(annotations, "\n        ") + `
      labels:
        app.kubernetes.io/name: lakom
        app.kubernetes.io/part-of: shoot-lakom-service
        networking.gardener.cloud/to-blocked-cidrs: allowed
        networking.gardener.cloud/to-dns: allowed
        networking.gardener.cloud/to-private-networks: allowed
        networking.gardener.cloud/to-public-networks: allowed
        networking.resources.gardener.cloud/to-kube-apiserver-tcp-443: allowed
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - podAffinityTerm:
              labelSelector:
                matchLabels:
                  app.kubernetes.io/name: lakom
                  app.kubernetes.io/part-of: shoot-lakom-service
              topologyKey: kubernetes.io/hostname
            weight: 100
      automountServiceAccountToken: false
      containers:
      - args:
        - --cache-ttl=10m0s
        - --cache-refresh-interval=30s
        - --lakom-config-path=/etc/lakom/config/config.yaml
        - --tls-cert-dir=/etc/lakom/tls
        - --health-bind-address=:8081
        - --metrics-bind-address=:8080
        - --port=10250
        - --kubeconfig=/var/run/secrets/gardener.cloud/shoot/generic-kubeconfig/kubeconfig
        - --use-only-image-pull-secrets=` + useOnlyImagePullSecrets + `
        - --insecure-allow-untrusted-images=` + allowUntrustedImages + `
        - --insecure-allow-insecure-registries=` + allowInsecureRegistries + `
        image: ` + image + `
        imagePullPolicy: IfNotPresent
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8081
            scheme: HTTP
          initialDelaySeconds: 10
        name: lakom
        ports:
        - containerPort: 10250
          name: https
          protocol: TCP
        - containerPort: 8080
          name: metrics
          protocol: TCP
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8081
            scheme: HTTP
          initialDelaySeconds: 5
        resources:
          requests:
            memory: 25M
        securityContext:
          allowPrivilegeEscalation: false
          privileged: false
        volumeMounts:
        - mountPath: /etc/lakom/config
          name: lakom-config
          readOnly: true
        - mountPath: /etc/lakom/tls
          name: lakom-server-tls
          readOnly: true
        - mountPath: /var/run/secrets/gardener.cloud/shoot/generic-kubeconfig
          name: kubeconfig
          readOnly: true
      priorityClassName: gardener-system-300
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      serviceAccountName: extension-shoot-lakom-service
      volumes:
      - configMap:
          name: ` + lakomConfigConfigMapName + `
        name: lakom-config
      - name: lakom-server-tls
        secret:
          secretName: ` + serverTLSSecretName + `
      - name: kubeconfig
        projected:
          defaultMode: 420
          sources:
          - secret:
              items:
              - key: kubeconfig
                path: kubeconfig
              name: ` + genericKubeconfigSecretName + `
              optional: false
          - secret:
              items:
              - key: token
                path: token
              name: ` + shootAccessSecretName + `
              optional: false
status: {}
`
}

func expectedSeedPDB(namespace string) string {
	return `apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service
  namespace: ` + namespace + `
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: lakom
      app.kubernetes.io/part-of: shoot-lakom-service
  unhealthyPodEvictionPolicy: AlwaysAllow
status:
  currentHealthy: 0
  desiredHealthy: 0
  disruptionsAllowed: 0
  expectedPods: 0
`
}

func expectedSeedConfigMapLakomConfig(namespace, lakomConfigSecretName string, lakomConfig string) string {

	return `apiVersion: v1
data:
  config.yaml: |
    ` + strings.TrimSuffix(strings.ReplaceAll(lakomConfig, "\n", "\n    "), "\n    ") + `
immutable: true
kind: ConfigMap
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    resources.gardener.cloud/garbage-collectable-reference: "true"
  name: ` + lakomConfigSecretName + `
  namespace: ` + namespace + `
`
}

func expectedSeedService(namespace string) string {
	return `apiVersion: v1
kind: Service
metadata:
  annotations:
    networking.resources.gardener.cloud/from-all-scrape-targets-allowed-ports: '[{"protocol":"TCP","port":8080}]'
    networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports: '[{"protocol":"TCP","port":10250}]'
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service
  namespace: ` + namespace + `
spec:
  ports:
  - name: https
    port: 443
    protocol: TCP
    targetPort: 10250
  - name: metrics
    port: 2718
    protocol: TCP
    targetPort: 8080
  selector:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  trafficDistribution: PreferSameZone
  type: ClusterIP
status:
  loadBalancer: {}
`
}

func expectedSeedServiceAccount(namespace, serviceAccountName string) string {
	return `apiVersion: v1
automountServiceAccountToken: false
kind: ServiceAccount
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: ` + serviceAccountName + `
  namespace: ` + namespace + `
`
}

func expectedSeedVPA(namespace string) string {
	return `apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service
  namespace: ` + namespace + `
spec:
  resourcePolicy:
    containerPolicies:
    - containerName: lakom
      controlledResources:
      - memory
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: extension-shoot-lakom-service
  updatePolicy:
    updateMode: InPlaceOrRecreate
status: {}
`
}

func expectedGardenVirtualDeployment(replicas int32, namespace, genericKubeconfigSecretName, gardenAccessSecretName, image, lakomConfigConfigMapName, serverTLSSecretName, useOnlyImagePullSecrets, allowUntrustedImages, allowInsecureRegistries string) string {
	var (
		genericKubeconfigSecretNameAnnotationKey = references.AnnotationKey("secret", genericKubeconfigSecretName)
		gardenAccessSecretNameAnnotationKey      = references.AnnotationKey("secret", gardenAccessSecretName)
		serverTLSSecretNameAnnotationKey         = references.AnnotationKey("secret", serverTLSSecretName)
		lakomConfigConfigMapNameAnnotationKey    = references.AnnotationKey("configmap", lakomConfigConfigMapName)

		annotations = []string{
			lakomConfigConfigMapNameAnnotationKey + ": " + lakomConfigConfigMapName,
			genericKubeconfigSecretNameAnnotationKey + ": " + genericKubeconfigSecretName,
			gardenAccessSecretNameAnnotationKey + ": " + gardenAccessSecretName,
			serverTLSSecretNameAnnotationKey + ": " + serverTLSSecretName,
		}
	)

	return `apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    ` + strings.Join(annotations, "\n    ") + `
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    high-availability-config.resources.gardener.cloud/type: server
  name: extension-shoot-lakom-service-garden-virtual
  namespace: ` + namespace + `
spec:
  replicas: ` + fmt.Sprintf("%d", replicas) + `
  revisionHistoryLimit: 2
  selector:
    matchLabels:
      app.kubernetes.io/instance: extension-shoot-lakom-service-garden-virtual
      app.kubernetes.io/name: lakom
      app.kubernetes.io/part-of: shoot-lakom-service
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
    type: RollingUpdate
  template:
    metadata:
      annotations:
        ` + strings.Join(annotations, "\n        ") + `
      labels:
        app.kubernetes.io/instance: extension-shoot-lakom-service-garden-virtual
        app.kubernetes.io/name: lakom
        app.kubernetes.io/part-of: shoot-lakom-service
        networking.gardener.cloud/to-blocked-cidrs: allowed
        networking.gardener.cloud/to-dns: allowed
        networking.gardener.cloud/to-private-networks: allowed
        networking.gardener.cloud/to-public-networks: allowed
        networking.resources.gardener.cloud/to-kube-apiserver-tcp-443: allowed
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - podAffinityTerm:
              labelSelector:
                matchLabels:
                  app.kubernetes.io/instance: extension-shoot-lakom-service-garden-virtual
                  app.kubernetes.io/name: lakom
                  app.kubernetes.io/part-of: shoot-lakom-service
              topologyKey: kubernetes.io/hostname
            weight: 100
      automountServiceAccountToken: false
      containers:
      - args:
        - --cache-ttl=10m0s
        - --cache-refresh-interval=30s
        - --lakom-config-path=/etc/lakom/config/config.yaml
        - --tls-cert-dir=/etc/lakom/tls
        - --health-bind-address=:8081
        - --metrics-bind-address=:8080
        - --port=10250
        - --kubeconfig=/var/run/secrets/gardener.cloud/shoot/generic-kubeconfig/kubeconfig
        - --use-only-image-pull-secrets=` + useOnlyImagePullSecrets + `
        - --insecure-allow-untrusted-images=` + allowUntrustedImages + `
        - --insecure-allow-insecure-registries=` + allowInsecureRegistries + `
        image: ` + image + `
        imagePullPolicy: IfNotPresent
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8081
            scheme: HTTP
          initialDelaySeconds: 10
        name: lakom
        ports:
        - containerPort: 10250
          name: https
          protocol: TCP
        - containerPort: 8080
          name: metrics
          protocol: TCP
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8081
            scheme: HTTP
          initialDelaySeconds: 5
        resources:
          requests:
            memory: 25M
        securityContext:
          allowPrivilegeEscalation: false
          privileged: false
        volumeMounts:
        - mountPath: /etc/lakom/config
          name: lakom-config
          readOnly: true
        - mountPath: /etc/lakom/tls
          name: lakom-server-tls
          readOnly: true
        - mountPath: /var/run/secrets/gardener.cloud/shoot/generic-kubeconfig
          name: kubeconfig
          readOnly: true
      priorityClassName: gardener-garden-system-200
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      serviceAccountName: extension-shoot-lakom-service-garden-virtual
      volumes:
      - configMap:
          name: ` + lakomConfigConfigMapName + `
        name: lakom-config
      - name: lakom-server-tls
        secret:
          secretName: ` + serverTLSSecretName + `
      - name: kubeconfig
        projected:
          defaultMode: 420
          sources:
          - secret:
              items:
              - key: kubeconfig
                path: kubeconfig
              name: ` + genericKubeconfigSecretName + `
              optional: false
          - secret:
              items:
              - key: token
                path: token
              name: ` + gardenAccessSecretName + `
              optional: false
status: {}
`
}

func expectedGardenVirtualPDB(namespace string) string {
	return `apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-virtual
  namespace: ` + namespace + `
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/instance: extension-shoot-lakom-service-garden-virtual
      app.kubernetes.io/name: lakom
      app.kubernetes.io/part-of: shoot-lakom-service
  unhealthyPodEvictionPolicy: AlwaysAllow
status:
  currentHealthy: 0
  desiredHealthy: 0
  disruptionsAllowed: 0
  expectedPods: 0
`
}

func expectedGardenVirtualService(namespace string) string {
	return `apiVersion: v1
kind: Service
metadata:
  annotations:
    networking.resources.gardener.cloud/from-all-scrape-targets-allowed-ports: '[{"protocol":"TCP","port":8080}]'
    networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports: '[{"protocol":"TCP","port":10250}]'
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-virtual
  namespace: ` + namespace + `
spec:
  ports:
  - name: https
    port: 443
    protocol: TCP
    targetPort: 10250
  - name: metrics
    port: 2718
    protocol: TCP
    targetPort: 8080
  selector:
    app.kubernetes.io/instance: extension-shoot-lakom-service-garden-virtual
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  trafficDistribution: PreferSameZone
  type: ClusterIP
status:
  loadBalancer: {}
`
}

func expectedGardenVirtualServiceAccount(namespace string) string {
	return `apiVersion: v1
automountServiceAccountToken: false
kind: ServiceAccount
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-virtual
  namespace: ` + namespace + `
`
}

func expectedGardenVirtualVPA(namespace string) string {
	return `apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-virtual
  namespace: ` + namespace + `
spec:
  resourcePolicy:
    containerPolicies:
    - containerName: lakom
      controlledResources:
      - memory
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: extension-shoot-lakom-service-garden-virtual
  updatePolicy:
    updateMode: Recreate
status: {}
`
}

func expectedGardenVirtualServiceMonitor(namespace string) string {
	return `apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    prometheus: garden-virtual
  name: garden-virtual-extension-shoot-lakom-service-garden-virtual
  namespace: ` + namespace + `
spec:
  endpoints:
  - metricRelabelings:
    - action: keep
      regex: ^(lakom.*)$
      sourceLabels:
      - __name__
    port: metrics
  namespaceSelector: {}
  selector:
    matchLabels:
      app.kubernetes.io/instance: extension-shoot-lakom-service-garden-virtual
      app.kubernetes.io/name: lakom
      app.kubernetes.io/part-of: shoot-lakom-service
`
}

func expectedGardenRuntimeDeployment(replicas int32, namespace, image, lakomConfigConfigMapName, serverTLSSecretName, useOnlyImagePullSecrets, allowUntrustedImages, allowInsecureRegistries string) string {
	var (
		serverTLSSecretNameAnnotationKey      = references.AnnotationKey("secret", serverTLSSecretName)
		lakomConfigConfigMapNameAnnotationKey = references.AnnotationKey("configmap", lakomConfigConfigMapName)

		annotations = []string{
			lakomConfigConfigMapNameAnnotationKey + ": " + lakomConfigConfigMapName,
			serverTLSSecretNameAnnotationKey + ": " + serverTLSSecretName,
		}
	)

	return `apiVersion: apps/v1
kind: Deployment
metadata:
  annotations:
    ` + strings.Join(annotations, "\n    ") + `
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
    high-availability-config.resources.gardener.cloud/type: server
  name: extension-shoot-lakom-service-garden-runtime
  namespace: ` + namespace + `
spec:
  replicas: ` + fmt.Sprintf("%d", replicas) + `
  revisionHistoryLimit: 2
  selector:
    matchLabels:
      app.kubernetes.io/instance: extension-shoot-lakom-service-garden-runtime
      app.kubernetes.io/name: lakom
      app.kubernetes.io/part-of: shoot-lakom-service
  strategy:
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
    type: RollingUpdate
  template:
    metadata:
      annotations:
        ` + strings.Join(annotations, "\n        ") + `
      labels:
        app.kubernetes.io/instance: extension-shoot-lakom-service-garden-runtime
        app.kubernetes.io/name: lakom
        app.kubernetes.io/part-of: shoot-lakom-service
        networking.gardener.cloud/to-blocked-cidrs: allowed
        networking.gardener.cloud/to-dns: allowed
        networking.gardener.cloud/to-private-networks: allowed
        networking.gardener.cloud/to-public-networks: allowed
        networking.resources.gardener.cloud/to-kube-apiserver-tcp-443: allowed
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - podAffinityTerm:
              labelSelector:
                matchLabels:
                  app.kubernetes.io/instance: extension-shoot-lakom-service-garden-runtime
                  app.kubernetes.io/name: lakom
                  app.kubernetes.io/part-of: shoot-lakom-service
              topologyKey: kubernetes.io/hostname
            weight: 100
      automountServiceAccountToken: true
      containers:
      - args:
        - --cache-ttl=10m0s
        - --cache-refresh-interval=30s
        - --lakom-config-path=/etc/lakom/config/config.yaml
        - --tls-cert-dir=/etc/lakom/tls
        - --health-bind-address=:8081
        - --metrics-bind-address=:8080
        - --port=10250
        - --use-only-image-pull-secrets=` + useOnlyImagePullSecrets + `
        - --insecure-allow-untrusted-images=` + allowUntrustedImages + `
        - --insecure-allow-insecure-registries=` + allowInsecureRegistries + `
        image: ` + image + `
        imagePullPolicy: IfNotPresent
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8081
            scheme: HTTP
          initialDelaySeconds: 10
        name: lakom
        ports:
        - containerPort: 10250
          name: https
          protocol: TCP
        - containerPort: 8080
          name: metrics
          protocol: TCP
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8081
            scheme: HTTP
          initialDelaySeconds: 5
        resources:
          requests:
            memory: 25M
        securityContext:
          allowPrivilegeEscalation: false
          privileged: false
        volumeMounts:
        - mountPath: /etc/lakom/config
          name: lakom-config
          readOnly: true
        - mountPath: /etc/lakom/tls
          name: lakom-server-tls
          readOnly: true
      priorityClassName: gardener-garden-system-200
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      serviceAccountName: extension-shoot-lakom-service-garden-runtime
      volumes:
      - configMap:
          name: ` + lakomConfigConfigMapName + `
        name: lakom-config
      - name: lakom-server-tls
        secret:
          secretName: ` + serverTLSSecretName + `
status: {}
`
}

func expectedGardenRuntimeNamespace(namespace string) string {
	return `apiVersion: v1
kind: Namespace
metadata:
  name: ` + namespace + `
spec: {}
status: {}
`
}

func expectedGardenRuntimePDB(namespace string) string {
	return `apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-runtime
  namespace: ` + namespace + `
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/instance: extension-shoot-lakom-service-garden-runtime
      app.kubernetes.io/name: lakom
      app.kubernetes.io/part-of: shoot-lakom-service
  unhealthyPodEvictionPolicy: AlwaysAllow
status:
  currentHealthy: 0
  desiredHealthy: 0
  disruptionsAllowed: 0
  expectedPods: 0
`
}

func expectedGardenRuntimeService(namespace string) string {
	return `apiVersion: v1
kind: Service
metadata:
  annotations:
    networking.resources.gardener.cloud/from-all-scrape-targets-allowed-ports: '[{"protocol":"TCP","port":8080}]'
    networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports: '[{"protocol":"TCP","port":10250}]'
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-runtime
  namespace: ` + namespace + `
spec:
  ports:
  - name: https
    port: 443
    protocol: TCP
    targetPort: 10250
  - name: metrics
    port: 2718
    protocol: TCP
    targetPort: 8080
  selector:
    app.kubernetes.io/instance: extension-shoot-lakom-service-garden-runtime
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  trafficDistribution: PreferSameZone
  type: ClusterIP
status:
  loadBalancer: {}
`
}

func expectedGardenRuntimeServiceAccount(namespace string) string {
	return `apiVersion: v1
automountServiceAccountToken: true
kind: ServiceAccount
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-runtime
  namespace: ` + namespace + `
`
}

func expectedGardenRuntimeRole(namespace string) string {
	return `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-runtime
  namespace: ` + namespace + `
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
  - list
  - watch
`
}

func expectedGardenRuntimeRoleBinding(namespace string) string {
	return `apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-runtime
  namespace: ` + namespace + `
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: extension-shoot-lakom-service-garden-runtime
subjects:
- kind: ServiceAccount
  name: extension-shoot-lakom-service-garden-runtime
  namespace: ` + namespace + `
`
}

func expectedGardenRuntimeVPA(namespace string) string {
	return `apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-garden-runtime
  namespace: ` + namespace + `
spec:
  resourcePolicy:
    containerPolicies:
    - containerName: lakom
      controlledResources:
      - memory
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: extension-shoot-lakom-service-garden-runtime
  updatePolicy:
    updateMode: Recreate
status: {}
`
}

func expectedGardenRuntimeServiceMonitor(namespace string) string {
	return `apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
    prometheus: garden-runtime
  name: garden-runtime-extension-shoot-lakom-service-garden-runtime
  namespace: ` + namespace + `
spec:
  endpoints:
  - metricRelabelings:
    - action: keep
      regex: ^(lakom.*)$
      sourceLabels:
      - __name__
    port: metrics
  namespaceSelector: {}
  selector:
    matchLabels:
      app.kubernetes.io/instance: extension-shoot-lakom-service-garden-runtime
      app.kubernetes.io/name: lakom
      app.kubernetes.io/part-of: shoot-lakom-service
`
}

func expectedGardenRuntimeTLSSecret(namespace, name string) string {
	return `apiVersion: v1
data:
  tls.crt: dGVzdC1jZXJ0
  tls.key: dGVzdC1rZXk=
kind: Secret
metadata:
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: ` + name + `
  namespace: ` + namespace + `
type: kubernetes.io/tls
`
}
