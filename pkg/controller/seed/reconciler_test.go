// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package seed

import (
	b64 "encoding/base64"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Reconciler", func() {

	It("Should get labels", func() {
		labels := getLabels()

		Expect(labels).To(HaveLen(2))
		appName, appNameOK := labels["app.kubernetes.io/name"]
		Expect(appNameOK).To(BeTrue())
		Expect(appName).To(Equal("lakom-seed"))

		appPartOf, appPartOfOK := labels["app.kubernetes.io/part-of"]
		Expect(appPartOfOK).To(BeTrue())
		Expect(appPartOf).To(Equal("shoot-lakom-service"))
	})

	Context("getResources", func() {
		const (
			namespace                = "kube-system"
			ownerNamespace           = "garden"
			lakomConfigConfigMapName = "extension-shoot-lakom-service-seed-lakom-config-5ccba116"
			serverTLSSecretName      = "shoot-lakom-service-seed-tls" //#nosec G101 -- this is false positive
			image                    = "europe-docker.pkg.dev/gardener-project/releases/gardener/extensions/lakom:v0.0.0"
			useOnlyImagePullSecrets  = true
			allowUntrustedImages     = false
			insecureRegistries       = false
		)

		var (
			lakomConfig string
			caBundle    = []byte("caBundle")
			k8sVersion  *semver.Version
		)

		BeforeEach(func() {
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

			k8sVersion = semver.MustParse("1.27.0")
		})

		DescribeTable("Should ensure resources are correctly created for different Kubernetes versions",
			func(k8sVersion string, withUnhealthyPodEvictionPolicy, onlyImagePullSecrets, untrustedImages, insecureRegistries bool) {
				resources, err := getResources(
					serverTLSSecretName,
					image,
					lakomConfig,
					caBundle,
					onlyImagePullSecrets,
					untrustedImages,
					insecureRegistries,
					semver.MustParse(k8sVersion),
				)

				Expect(err).ToNot(HaveOccurred())
				Expect(resources).To(HaveKey("data.yaml.br"))
				compressedData := resources["data.yaml.br"]
				data, err := test.BrotliDecompression(compressedData)
				Expect(err).NotTo(HaveOccurred())

				manifests := strings.Split(string(data), "\n---\n") // Just '---\n' does not work because of the header/footer in the public keys that match the same manifest separator
				Expect(manifests).To(HaveLen(10))

				for i := range manifests { // Re-add the trailing '\n' removed during the split from the separator above
					if i < len(manifests)-1 {
						manifests[i] += "\n"
					}
				}

				Expect(manifests).To(ConsistOf(
					expectedValidatingWebhook(caBundle),
					expectedMutatingWebhook(caBundle),
					expectedClusterRole(),
					expectedClusterRoleBinding(),
					expectedDeployment(namespace, image, lakomConfigConfigMapName, serverTLSSecretName, strconv.FormatBool(onlyImagePullSecrets), strconv.FormatBool(untrustedImages), strconv.FormatBool(insecureRegistries)),
					expectedPDB(namespace, withUnhealthyPodEvictionPolicy),
					expectedConfigMapLakomConfig(namespace, lakomConfigConfigMapName, lakomConfig),
					expectedService(namespace),
					expectedServiceAccount(namespace),
					expectedVPA(namespace),
				))
			},
			Entry("Kubernetes version < 1.26", "1.25.0", false, false, false, false),
			Entry("Kubernetes version >= 1.26", "1.26.0", true, false, false, false),
			Entry("Use only image pull secrets", "1.27.0", true, true, false, false),
			Entry("Allow untrusted images", "1.28.0", true, false, true, false),
			Entry("Allow insecure registries", "1.29.0", true, false, true, true),
		)

		DescribeTable("Should ensure the mutating webhook config is correctly set",
			func(ca []byte) {
				resources, err := getResources(
					serverTLSSecretName,
					image,
					lakomConfig,
					ca,
					useOnlyImagePullSecrets,
					allowUntrustedImages,
					insecureRegistries,
					k8sVersion,
				)
				Expect(err).ToNot(HaveOccurred())
				manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
				Expect(err).ToNot(HaveOccurred())

				Expect(manifests).To(ContainElement(expectedMutatingWebhook(ca)))
			},
			Entry("Global CA bundle", caBundle),
			Entry("Custom CA bundle", []byte("anotherCABundle")),
		)

		DescribeTable("Should ensure the validating webhook config is correctly set",
			func(ca []byte) {
				resources, err := getResources(
					serverTLSSecretName,
					image,
					lakomConfig,
					ca,
					useOnlyImagePullSecrets,
					allowUntrustedImages,
					insecureRegistries,
					k8sVersion,
				)
				Expect(err).ToNot(HaveOccurred())
				manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
				Expect(err).ToNot(HaveOccurred())

				Expect(manifests).To(ContainElement(expectedValidatingWebhook(ca)))
			},
			Entry("Global CA bundle", caBundle),
			Entry("Custom ca bundle", []byte("anotherCABundle")),
		)

		It("Should ensure the clusterrolebinding is correctly set", func() {
			resources, err := getResources(
				serverTLSSecretName,
				image,
				lakomConfig,
				caBundle,
				useOnlyImagePullSecrets,
				allowUntrustedImages,
				insecureRegistries,
				k8sVersion,
			)
			Expect(err).ToNot(HaveOccurred())
			manifests, err := test.ExtractManifestsFromManagedResourceData(resources)
			Expect(err).ToNot(HaveOccurred())

			Expect(manifests).To(ContainElement(expectedClusterRoleBinding()))
		})
	})
})

func expectedMutatingWebhook(caBundle []byte) string {
	var (
		caBundleEncoded = b64.StdEncoding.EncodeToString(caBundle)
	)

	return `apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: gardener-extension-shoot-lakom-service-seed
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ` + caBundleEncoded + `
    service:
      name: extension-shoot-lakom-service-seed
      namespace: kube-system
      path: /lakom/resolve-tag-to-digest
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: resolve-tag.seed.lakom.service.extensions.gardener.cloud
  namespaceSelector:
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values:
      - kube-system
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

func expectedValidatingWebhook(caBundle []byte) string {
	var (
		caBundleEncoded = b64.StdEncoding.EncodeToString(caBundle)
	)
	return `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: gardener-extension-shoot-lakom-service-seed
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ` + caBundleEncoded + `
    service:
      name: extension-shoot-lakom-service-seed
      namespace: kube-system
      path: /lakom/verify-cosign-signature
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: verify-signature.seed.lakom.service.extensions.gardener.cloud
  namespaceSelector:
    matchExpressions:
    - key: kubernetes.io/metadata.name
      operator: NotIn
      values:
      - kube-system
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

func expectedClusterRole() string {
	return `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-seed
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
`
}

func expectedClusterRoleBinding() string {
	return `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-seed
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: extension-shoot-lakom-service-seed
subjects:
- kind: ServiceAccount
  name: extension-shoot-lakom-service-seed
  namespace: kube-system
`
}

func expectedDeployment(namespace, image, lakomConfigConfigMapName, serverTLSSecretName, useOnlyImagePullSecrets, allowUntrustedImages, allowInsecureRegistries string) string {
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
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
    high-availability-config.resources.gardener.cloud/type: server
  name: extension-shoot-lakom-service-seed
  namespace: ` + namespace + `
spec:
  replicas: 3
  revisionHistoryLimit: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: lakom-seed
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
        app.kubernetes.io/name: lakom-seed
        app.kubernetes.io/part-of: shoot-lakom-service
        networking.gardener.cloud/to-blocked-cidrs: allowed
        networking.gardener.cloud/to-dns: allowed
        networking.gardener.cloud/to-public-networks: allowed
        networking.gardener.cloud/to-runtime-apiserver: allowed
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - podAffinityTerm:
              labelSelector:
                matchLabels:
                  app.kubernetes.io/name: lakom-seed
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
        name: lakom-seed
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
        volumeMounts:
        - mountPath: /etc/lakom/config
          name: lakom-config
          readOnly: true
        - mountPath: /etc/lakom/tls
          name: lakom-server-tls
          readOnly: true
      priorityClassName: gardener-system-900
      serviceAccountName: extension-shoot-lakom-service-seed
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

func expectedPDB(namespace string, withUnhealthyPodEvictionPolicy bool) string {
	out := `apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-seed
  namespace: ` + namespace + `
spec:
  maxUnavailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: lakom-seed
      app.kubernetes.io/part-of: shoot-lakom-service
`
	if withUnhealthyPodEvictionPolicy {
		out += `  unhealthyPodEvictionPolicy: AlwaysAllow
`
	}
	out += `status:
  currentHealthy: 0
  desiredHealthy: 0
  disruptionsAllowed: 0
  expectedPods: 0
`
	return out
}

func expectedConfigMapLakomConfig(namespace, lakomConfigSecretName, lakomConfig string) string {

	return `apiVersion: v1
data:
  config.yaml: |
    ` + strings.TrimSuffix(strings.ReplaceAll(lakomConfig, "\n", "\n    "), "\n    ") + `
immutable: true
kind: ConfigMap
metadata:
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
    resources.gardener.cloud/garbage-collectable-reference: "true"
  name: ` + lakomConfigSecretName + `
  namespace: ` + namespace + `
`
}

func expectedService(namespace string) string {
	return `apiVersion: v1
kind: Service
metadata:
  annotations:
    networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports: '[{"protocol":"TCP","port":10250}]'
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-seed
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
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
  type: ClusterIP
status:
  loadBalancer: {}
`
}

func expectedServiceAccount(namespace string) string {
	return `apiVersion: v1
automountServiceAccountToken: false
kind: ServiceAccount
metadata:
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-seed
  namespace: ` + namespace + `
`
}

func expectedVPA(namespace string) string {
	return `apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  creationTimestamp: null
  labels:
    app.kubernetes.io/name: lakom-seed
    app.kubernetes.io/part-of: shoot-lakom-service
  name: extension-shoot-lakom-service-seed
  namespace: ` + namespace + `
spec:
  resourcePolicy:
    containerPolicies:
    - containerName: lakom-seed
      controlledResources:
      - memory
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: extension-shoot-lakom-service-seed
  updatePolicy:
    updateMode: Auto
status: {}
`
}
