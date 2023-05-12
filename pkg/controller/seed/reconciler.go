// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package seed

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/imagevector"

	"github.com/Masterminds/semver"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	"github.com/gardener/gardener/pkg/utils"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	admissionregistration "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/component-base/version"
	"k8s.io/utils/clock"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type kubeSystemReconciler struct {
	client         client.Client
	serviceConfig  config.Configuration
	serverVersion  string
	ownerNamespace string
}

// Reconcile installs the lakom admission controller in the kube-system namespace.
func (kcr *kubeSystemReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	if request.Name != metav1.NamespaceSystem {
		return reconcile.Result{}, nil
	}

	logger := log.FromContext(ctx)
	if err := kcr.reconcile(ctx, logger); err != nil {
		return reconcile.Result{Requeue: true}, err
	}

	return reconcile.Result{}, nil
}

func (kcr *kubeSystemReconciler) reconcile(ctx context.Context, logger logr.Logger) error {
	const (
		kubeSystemNamespaceName = metav1.NamespaceSystem
	)

	secretsConfig := ConfigsFor(kubeSystemNamespaceName)
	secretsManager, err := secretsmanager.New(ctx, logger.WithName("seed-secretsmanager"), clock.RealClock{}, kcr.client, kubeSystemNamespaceName, ManagerIdentity, secretsmanager.Config{})
	if err != nil {
		return err
	}
	generatedSecrets, err := extensionssecretsmanager.GenerateAllSecrets(ctx, secretsManager, secretsConfig)
	if err != nil {
		return err
	}
	caBundleSecret, found := secretsManager.Get(CAName)
	if !found {
		return fmt.Errorf("secret %q not found", CAName)
	}

	serverVersion, err := semver.NewVersion(kcr.serverVersion)
	if err != nil {
		return err
	}

	image, err := imagevector.ImageVector().FindImage(constants.ImageName)
	if err != nil {
		return fmt.Errorf("failed to find image version for %s: %v", constants.ImageName, err)
	}
	if image.Tag == nil {
		image.Tag = pointer.String(version.Get().GitVersion)
	}

	var (
		failurePolicy          = admissionregistration.Fail
		allowedFailurePolicies = sets.NewString(string(admissionregistration.Fail), string(admissionregistration.Ignore))
	)
	if kcr.serviceConfig.FailurePolicy != nil && allowedFailurePolicies.Has(*kcr.serviceConfig.FailurePolicy) {
		failurePolicy = admissionregistration.FailurePolicyType(*kcr.serviceConfig.FailurePolicy)
	}

	resources, err := getResources(
		kcr.ownerNamespace,
		generatedSecrets[constants.WebhookTLSSecretName].Name,
		image.String(),
		kcr.serviceConfig.CosignPublicKeys,
		caBundleSecret.Data[secretutils.DataKeyCertificateBundle],
		failurePolicy,
		serverVersion,
	)
	if err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, kcr.client, kubeSystemNamespaceName, constants.SeedApplicationName, false, resources); err != nil { // TODO(vpnachev): Put the MR in the garden namespace? The resources are still deployed in kube-system.
		return err
	}

	twoMinutes := 2 * time.Minute
	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelSeedCtx()
	if err := managedresources.WaitUntilHealthy(timeoutSeedCtx, kcr.client, kubeSystemNamespaceName, constants.SeedApplicationName); err != nil {
		return err
	}

	if err := kcr.setOwnerRef(ctx, kubeSystemNamespaceName); err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

func (kcr *kubeSystemReconciler) setOwnerRef(ctx context.Context, namespace string) error {
	ownerNamespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: kcr.ownerNamespace}}
	if err := kcr.client.Get(ctx, client.ObjectKeyFromObject(ownerNamespace), ownerNamespace); err != nil {
		return err
	}

	mr := &resourcesv1alpha1.ManagedResource{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: constants.SeedApplicationName}}
	if err := kcr.client.Get(ctx, client.ObjectKeyFromObject(mr), mr); err != nil {
		return err
	}

	patch := client.MergeFrom(mr)
	ownerRef := metav1.NewControllerRef(ownerNamespace, corev1.SchemeGroupVersion.WithKind("Namespace"))
	ownerRef.BlockOwnerDeletion = pointer.Bool(false)
	mr.SetOwnerReferences(kutil.MergeOwnerReferences(mr.OwnerReferences, *ownerRef))

	return kcr.client.Patch(ctx, mr, patch)
}

func getLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":    constants.SeedApplicationName,
		"app.kubernetes.io/part-of": constants.ExtensionType,
	}
}

func getResources(ownerNamespace, serverTLSSecretName, image string, cosignPublicKeys []string, webhookCaBundle []byte, failurePolicy admissionregistration.FailurePolicyType, serverVersion *semver.Version) (map[string][]byte, error) {
	var (
		tcpProto                   = corev1.ProtocolTCP
		serverPort                 = intstr.FromInt(10250)
		metricsPort                = intstr.FromInt(8080)
		healthPort                 = intstr.FromInt(8081)
		cacheTTL                   = time.Minute * 10
		cacheRefreshInterval       = time.Second * 30
		cosignPublicKeysDir        = "/etc/lakom/cosign"
		cosignPublicKeysSecretName = constants.ExtensionServiceName + "-cosign-public-keys"
		webhookTLSCertDir          = "/etc/lakom/tls"
		registry                   = managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)
		requestCPU, _              = resource.ParseQuantity("50m")
		requestMemory, _           = resource.ParseQuantity("64Mi")
		vpaUpdateMode              = vpaautoscalingv1.UpdateModeAuto
		kubeSystemNamespace        = metav1.NamespaceSystem
		matchPolicy                = admissionregistration.Equivalent
		sideEffectClass            = admissionregistration.SideEffectClassNone
		timeOutSeconds             = pointer.Int32(25)
		namespaceSelector          = metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      corev1.LabelMetadataName,
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{kubeSystemNamespace},
				},
			},
		}
		rules = []admissionregistration.RuleWithOperations{{
			Operations: []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
			Rule: admissionregistration.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods", "pods/ephemeralcontainers"},
			},
		}}
		webhookName = constants.GardenerExtensionName + "-seed"
	)

	cosignPublicKeysSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cosignPublicKeysSecretName,
			Namespace: kubeSystemNamespace,
			Labels:    getLabels(),
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"cosign.pub": strings.Join(cosignPublicKeys, "\n"),
		},
	}

	if err := kutil.MakeUnique(&cosignPublicKeysSecret); err != nil {
		return nil, err
	}

	lakomDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ExtensionServiceName,
			Namespace: kubeSystemNamespace,
			Labels: utils.MergeStringMaps(getLabels(), map[string]string{
				resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
			}),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             pointer.Int32(3),
			RevisionHistoryLimit: pointer.Int32(2),
			Selector:             &metav1.LabelSelector{MatchLabels: getLabels()},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
					MaxSurge:       &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: utils.MergeStringMaps(getLabels(), map[string]string{
						v1beta1constants.LabelNetworkPolicyToDNS:              v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPublicNetworks:   v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToRuntimeAPIServer: v1beta1constants.LabelNetworkPolicyAllowed,
					}),
				},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
								Weight: 100,
								PodAffinityTerm: corev1.PodAffinityTerm{
									TopologyKey:   corev1.LabelHostname,
									LabelSelector: &metav1.LabelSelector{MatchLabels: getLabels()},
								},
							}},
						},
					},
					ServiceAccountName: constants.ExtensionServiceName,
					Containers: []corev1.Container{{
						Name:            constants.SeedApplicationName,
						Image:           image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Args: []string{
							"--cache-ttl=" + cacheTTL.String(),
							"--cache-refresh-interval=" + cacheRefreshInterval.String(),
							"--cosign-public-key-path=" + cosignPublicKeysDir + "/cosign.pub",
							"--tls-cert-dir=" + webhookTLSCertDir,
							"--health-bind-address=:" + healthPort.String(),
							"--metrics-bind-address=:" + metricsPort.String(),
							"--port=" + serverPort.String(),
							// "--kubeconfig=/etc/lakom/client/kubeconfig", // Should discover automatically the in-cluster kubeconfig
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "https",
								Protocol:      tcpProto,
								ContainerPort: int32(serverPort.IntValue()),
							},
							{
								Name:          "metrics",
								Protocol:      tcpProto,
								ContainerPort: int32(metricsPort.IntValue()),
							},
						},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/healthz",
									Port:   healthPort,
									Scheme: corev1.URISchemeHTTP,
								},
							},
							InitialDelaySeconds: 10,
						},
						ReadinessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{
								HTTPGet: &corev1.HTTPGetAction{
									Path:   "/readyz",
									Port:   healthPort,
									Scheme: corev1.URISchemeHTTP,
								},
							},
							InitialDelaySeconds: 5,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    requestCPU,
								corev1.ResourceMemory: requestMemory,
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "lakom-public-keys",
								MountPath: cosignPublicKeysDir,
								ReadOnly:  true,
							},
							{
								Name:      "lakom-server-tls",
								ReadOnly:  true,
								MountPath: webhookTLSCertDir,
							},
						},
					}},
					PriorityClassName: v1beta1constants.PriorityClassNameSeedSystem900,
					Volumes: []corev1.Volume{
						{
							Name: "lakom-public-keys",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: cosignPublicKeysSecret.Name,
								},
							},
						},
						{
							Name: "lakom-server-tls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: serverTLSSecretName,
								},
							},
						},
					},
				},
			},
		},
	}
	lakomDeployment.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("Deployment"))

	if err := references.InjectAnnotations(lakomDeployment); err != nil {
		return nil, err
	}

	lakomPDB, err := getPDB(kubeSystemNamespace, serverVersion)
	if err != nil {
		return nil, err
	}

	lakomService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ExtensionServiceName,
			Namespace: kubeSystemNamespace,
			Labels:    getLabels(),
			Annotations: map[string]string{
				"networking.resources.gardener.cloud/from-all-scrape-targets-allowed-ports":  `[{"protocol":"TCP","port":` + metricsPort.String() + `}]`,
				"networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports": `[{"protocol":"TCP","port":` + serverPort.String() + `}]`,
				// TODO: This annotation approach is deprecated and no longer needed in the future. Remove them as soon as gardener/gardener@v1.75 has been released.
				"networking.resources.gardener.cloud/from-policy-allowed-ports":      `[{"protocol":"TCP","port":` + metricsPort.String() + `}]`,
				"networking.resources.gardener.cloud/from-policy-pod-label-selector": "all-scrape-targets",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: getLabels(),
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Protocol:   tcpProto,
					Port:       443,
					TargetPort: serverPort,
				},
				{
					Name:       "metrics",
					Protocol:   tcpProto,
					Port:       2718,
					TargetPort: metricsPort,
				},
			},
		},
	}

	var ()

	resources, err := registry.AddAllAndSerialize(
		lakomDeployment,
		lakomPDB,
		&cosignPublicKeysSecret,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ExtensionServiceName,
				Namespace: kubeSystemNamespace,
				Labels:    getLabels(),
			},
			AutomountServiceAccountToken: pointer.Bool(false),
		},
		lakomService,
		&vpaautoscalingv1.VerticalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ExtensionServiceName,
				Namespace: kubeSystemNamespace,
				Labels:    getLabels(),
			},
			Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
				ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
					ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{
						{
							ContainerName: constants.ApplicationName,
							MinAllowed: corev1.ResourceList{
								corev1.ResourceMemory: resource.MustParse("32Mi"),
							},
						},
					},
				},
				TargetRef: &autoscalingv1.CrossVersionObjectReference{
					APIVersion: lakomDeployment.APIVersion,
					Kind:       lakomDeployment.Kind,
					Name:       lakomDeployment.Name,
				},
				UpdatePolicy: &vpaautoscalingv1.PodUpdatePolicy{
					UpdateMode: &vpaUpdateMode,
				},
			},
		},
		&corev1.ConfigMap{ // TODO(vpnachev): Is this working outside of shoot namespaces?
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ExtensionServiceName + "-monitoring",
				Namespace: kubeSystemNamespace,
				Labels:    utils.MergeStringMaps(getLabels(), map[string]string{v1beta1constants.LabelExtensionConfiguration: v1beta1constants.LabelMonitoring}),
			},
			Data: map[string]string{
				v1beta1constants.PrometheusConfigMapScrapeConfig: `- job_name: ` + constants.ExtensionServiceName + `
  honor_labels: false
  kubernetes_sd_configs:
  - role: endpoints
    namespaces:
      names: [` + kubeSystemNamespace + `]
  relabel_configs:
  - source_labels:
    - __meta_kubernetes_service_name
    - __meta_kubernetes_endpoint_port_name
    action: keep
    regex: ` + constants.ExtensionServiceName + `;metrics
  # common metrics
  - action: drop
    regex: __meta_kubernetes_service_label_(.+)
  - source_labels: [ __meta_kubernetes_pod_name ]
    target_label: pod
  - source_labels: [ __meta_kubernetes_pod_container_name ]
    target_label: container
  metric_relabel_configs:
  - source_labels: [ __name__ ]
    regex: ^lakom.*$
    action: keep
`,
			},
		},

		&admissionregistration.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:   webhookName,
				Labels: utils.MergeStringMaps(getLabels(), map[string]string{v1beta1constants.LabelExcludeWebhookFromRemediation: "true"}),
			},
			Webhooks: []admissionregistration.MutatingWebhook{{
				Name:                    "resolve-tag.seed.lakom.service.extensions.gardener.cloud",
				Rules:                   rules,
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				SideEffects:             &sideEffectClass,
				TimeoutSeconds:          timeOutSeconds,
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admissionregistration.WebhookClientConfig{
					Service: &admissionregistration.ServiceReference{
						Namespace: kubeSystemNamespace,
						Name:      constants.ExtensionServiceName,
						Path:      pointer.String(constants.LakomResolveTagPath),
					},
					CABundle: webhookCaBundle,
				},
				NamespaceSelector: &namespaceSelector,
			}},
		},
		&admissionregistration.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:   webhookName,
				Labels: utils.MergeStringMaps(getLabels(), map[string]string{v1beta1constants.LabelExcludeWebhookFromRemediation: "true"}),
			},
			Webhooks: []admissionregistration.ValidatingWebhook{{
				Name:                    "verify-signature.seed.lakom.service.extensions.gardener.cloud",
				Rules:                   rules,
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				SideEffects:             &sideEffectClass,
				TimeoutSeconds:          timeOutSeconds,
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admissionregistration.WebhookClientConfig{
					Service: &admissionregistration.ServiceReference{
						Namespace: kubeSystemNamespace,
						Name:      constants.ExtensionServiceName,
						Path:      pointer.String(constants.LakomVerifyCosignSignaturePath),
					},
					CABundle: webhookCaBundle,
				},
				NamespaceSelector: &namespaceSelector,
			}},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   webhookName,
				Labels: getLabels(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get"},
				},
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   webhookName,
				Labels: getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     webhookName,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      constants.ExtensionServiceName, // TODO(vpnachev): For managed seeds, there is already such service account!
					Namespace: kubeSystemNamespace,
				},
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return resources, nil
}

func getPDB(namespaceName string, k8sVersion *semver.Version) (client.Object, error) {
	var (
		maxUnavailable = intstr.FromInt(1)
		labels         = getLabels()
	)

	constraintK8sLess121, err := semver.NewConstraint("< 1.21-0")
	if err != nil {
		return nil, err
	}

	if constraintK8sLess121.Check(k8sVersion) {
		return &policyv1beta1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ExtensionServiceName,
				Namespace: namespaceName,
				Labels:    getLabels(),
			},
			Spec: policyv1beta1.PodDisruptionBudgetSpec{
				MaxUnavailable: &maxUnavailable,
				Selector:       &metav1.LabelSelector{MatchLabels: labels},
			},
		}, nil
	}

	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ExtensionServiceName,
			Namespace: namespaceName,
			Labels:    getLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector:       &metav1.LabelSelector{MatchLabels: labels},
		},
	}, nil
}
