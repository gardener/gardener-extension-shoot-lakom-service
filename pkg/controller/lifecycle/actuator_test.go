// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	b64 "encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"

	"github.com/Masterminds/semver/v3"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

	Context("getShootResources", func() {
		const (
			shootNamespace                  = "garden-foo"
			extensionNamespace              = "shoot--foo--bar"
			scope                           = lakom.KubeSystemManagedByGardener
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
			emptyNamespaceSelector = ` {}`
		)
		var (
			caBundle = []byte("caBundle")
		)

		It("Should ensure the correct shoot resources are created", func() {

			resources, err := getShootResources(caBundle, extensionNamespace, shootAccessServiceAccountName, scope)
			Expect(err).ToNot(HaveOccurred())
			manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
			Expect(err).ToNot(HaveOccurred())

			Expect(manifests).To(ConsistOf(
				expectedSeedValidatingWebhook(caBundle, extensionNamespace, managedByGardenerObjectSelector, kubeSystemNamespaceSelector),
				expectedShootMutatingWebhook(caBundle, extensionNamespace, managedByGardenerObjectSelector, kubeSystemNamespaceSelector),
				expectedShootClusterRole(),
				expectedShootRoleBinding(shootAccessServiceAccountName, scope),
			))
		})

		DescribeTable("Should ensure the mutating webhook config is correctly set",
			func(ca []byte, ns string) {
				resources, err := getShootResources(ca, ns, shootAccessServiceAccountName, scope)
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
				resources, err := getShootResources(ca, ns, shootAccessServiceAccountName, scope)
				Expect(err).ToNot(HaveOccurred())
				manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
				Expect(err).ToNot(HaveOccurred())

				Expect(manifests).To(ContainElement(expectedSeedValidatingWebhook(ca, ns, managedByGardenerObjectSelector, kubeSystemNamespaceSelector)))
			},
			Entry("Global CA bundle and namespace name", caBundle, extensionNamespace),
			Entry("Custom CA bundle and namespace name", []byte("anotherCABundle"), "different-namespace"),
		)

		DescribeTable("Should return an empty object selector for the webhooks when shoot is in the garden namespace",
			func(ca []byte, ns string) {
				resources, err := getShootResources(ca, ns, shootAccessServiceAccountName, v1beta1constants.GardenNamespace)
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
			func(saName string, lakomScope lakom.ScopeType) {
				resources, err := getShootResources(caBundle, extensionNamespace, saName, lakomScope)
				Expect(err).ToNot(HaveOccurred())
				manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
				Expect(err).ToNot(HaveOccurred())

				Expect(manifests).To(ContainElement(expectedShootRoleBinding(saName, lakomScope)))
			},
			Entry("ServiceAccount name: test, scope: KubeSystemManagedByGardener", "test", lakom.KubeSystemManagedByGardener),
			Entry("ServiceAccount name: foo-bar, scope: KubeSystem", "foo-bar", lakom.KubeSystem),
			Entry("ServiceAccount name: foo-bar, scope: Cluster", "foo-bar", lakom.Cluster),
		)

		DescribeTable("Should return the correct object and namespace selectors based on scope",
			func(scope lakom.ScopeType, objectSelector, namespaceSelector string) {
				resources, err := getShootResources(caBundle, extensionNamespace, shootAccessServiceAccountName, scope)
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

		DescribeTable("Should ensure resources are correctly created for different Kubernetes versions",
			func(k8sVersion *semver.Version, withUnhealthyPodEvictionPolicy, useOnlyImagePullSecrets, allowUntrustedImages, allowInsecureRegistries bool) {
				resources, err := getSeedResources(
					&replicas,
					namespace,
					genericKubeconfigName,
					shootAccessServiceAccountName,
					serverTLSSecretName,
					lakomConfig,
					image,
					useOnlyImagePullSecrets,
					allowUntrustedImages,
					allowInsecureRegistries,
					k8sVersion,
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
					expectedSeedPDB(namespace, withUnhealthyPodEvictionPolicy),
					expectedSeedConfigMapLakomConfig(namespace, lakomConfigConfigMapName, lakomConfig),
					expectedSeedService(namespace),
					expectedSeedServiceAccount(namespace, shootAccessServiceAccountName),
					expectedSeedVPA(namespace),
					expectedSeedServiceMonitor(namespace),
				))
			},
			Entry("Kubernetes version < 1.26", semver.MustParse("1.25.0"), false, false, false, false),
			Entry("Kubernetes version >= 1.26", semver.MustParse("1.26.0"), true, false, false, false),
			Entry("Use only image pull secrets", semver.MustParse("1.27.0"), true, true, false, false),
			Entry("Allow untrusted images", semver.MustParse("1.28.0"), true, false, true, false),
			Entry("Allow insecure registries", semver.MustParse("1.29.0"), true, false, false, true),
		)
	})
})

func expectedShootMutatingWebhook(caBundle []byte, namespace string, objectSelector string, namespaceSelector string) string {
	caBundleEncoded := b64.StdEncoding.EncodeToString(caBundle)

	return `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  creationTimestamp: null
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
  creationTimestamp: null
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

func expectedShootClusterRole() string {
	return `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  creationTimestamp: null
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

func expectedShootRoleBinding(saName string, lakomScope lakom.ScopeType) string {
	if lakomScope == lakom.Cluster {
		return `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  creationTimestamp: null
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
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom
    app.kubernetes.io/part-of: shoot-lakom-service
  name: gardener-extension-shoot-lakom-service-resource-reader
  namespace: kube-system
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
  creationTimestamp: null
  labels:
    prometheus: shoot
  name: shoot-extension-shoot-lakom-service
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
  creationTimestamp: null
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
      creationTimestamp: null
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

func expectedSeedPDB(namespace string, withUnhealthyPodEvictionPolicy bool) string {
	unhealthyPodEvictionPolicyStr := ""
	if withUnhealthyPodEvictionPolicy {
		unhealthyPodEvictionPolicyStr = `  unhealthyPodEvictionPolicy: AlwaysAllow
`
	}
	return `apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  creationTimestamp: null
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
` + unhealthyPodEvictionPolicyStr + `status:
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
  creationTimestamp: null
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
  creationTimestamp: null
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
  creationTimestamp: null
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
  creationTimestamp: null
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
    updateMode: Auto
status: {}
`
}
