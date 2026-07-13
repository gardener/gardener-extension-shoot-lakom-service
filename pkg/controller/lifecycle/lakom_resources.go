package lifecycle

import (
	"fmt"
	"strconv"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	kubeapiserverconstants "github.com/gardener/gardener/pkg/component/kubernetes/apiserver/constants"
	monitoringutils "github.com/gardener/gardener/pkg/component/observability/monitoring/utils"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	"github.com/gardener/gardener/pkg/utils"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	shootWebhookRules []admissionregistrationv1.RuleWithOperations = []admissionregistrationv1.RuleWithOperations{{
		Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
		Rule: admissionregistrationv1.Rule{
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods", "pods/ephemeralcontainers"},
		},
	}}

	gardenWebhookRuntimeRules []admissionregistrationv1.RuleWithOperations = []admissionregistrationv1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{""},
				APIVersions: []string{"v1"},
				Resources:   []string{"pods", "pods/ephemeralcontainers"},
			},
		},
		{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"operator.gardener.cloud"},
				APIVersions: []string{"v1alpha1"},
				Resources:   []string{"extensions"},
			},
		},
	}

	gardenWebhookVirtualGardenRules []admissionregistrationv1.RuleWithOperations = []admissionregistrationv1.RuleWithOperations{
		{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"core.gardener.cloud"},
				APIVersions: []string{"v1"},
				Resources:   []string{"controllerdeployments"},
			},
		},
		{
			Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{"seedmanagement.gardener.cloud"},
				APIVersions: []string{"v1alpha1"},
				Resources:   []string{"gardenlets"},
			},
		},
	}
)

func getWebhookResources(
	webhookVariant webhookVariant,
	webhookCaBundle []byte,
	webhookRRules []admissionregistrationv1.RuleWithOperations,
	serviceName,
	extensionNamespace string,
	scope lakom.ScopeType,
	dashboardEnabled bool,
) (map[string][]byte, error) {
	clientConfigFor := func(path string) admissionregistrationv1.WebhookClientConfig {
		if webhookVariant.useServiceClientConfig {
			return serviceBasedWebhookClientConfig(webhookCaBundle, extensionNamespace, serviceName, path)
		}
		return urlBasedWebhookClientConfig(webhookCaBundle, fmt.Sprintf("%s.%s", serviceName, extensionNamespace), path)
	}

	var (
		matchPolicy       = admissionregistrationv1.Equivalent
		sideEffectClass   = admissionregistrationv1.SideEffectClassNone
		failurePolicy     = admissionregistrationv1.Fail
		timeOutSeconds    = ptr.To[int32](25)
		namespaceSelector = scopeToNamespaceSelector(scope, dashboardEnabled)
		objectSelector    = scopeToObjectSelector(scope)
		clientObjects     = []client.Object{
			&admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:   webhookVariant.configName,
					Labels: utils.MergeStringMaps(getLabels(), map[string]string{v1beta1constants.LabelExcludeWebhookFromRemediation: "true"}),
				},
				Webhooks: []admissionregistrationv1.MutatingWebhook{{
					Name:                    "resolve-tag.lakom.service.extensions.gardener.cloud",
					Rules:                   webhookRRules,
					FailurePolicy:           &failurePolicy,
					MatchPolicy:             &matchPolicy,
					SideEffects:             &sideEffectClass,
					TimeoutSeconds:          timeOutSeconds,
					AdmissionReviewVersions: []string{"v1"},
					ClientConfig:            clientConfigFor(constants.LakomResolveTagPath),
					NamespaceSelector:       &namespaceSelector,
					ObjectSelector:          &objectSelector,
				}},
			},
			&admissionregistrationv1.ValidatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:   webhookVariant.configName,
					Labels: utils.MergeStringMaps(getLabels(), map[string]string{v1beta1constants.LabelExcludeWebhookFromRemediation: "true"}),
				},
				Webhooks: []admissionregistrationv1.ValidatingWebhook{{
					Name:                    "verify-signature.lakom.service.extensions.gardener.cloud",
					Rules:                   webhookRRules,
					FailurePolicy:           &failurePolicy,
					MatchPolicy:             &matchPolicy,
					SideEffects:             &sideEffectClass,
					TimeoutSeconds:          timeOutSeconds,
					AdmissionReviewVersions: []string{"v1"},
					ClientConfig:            clientConfigFor(constants.LakomVerifyCosignSignaturePath),
					NamespaceSelector:       &namespaceSelector,
					ObjectSelector:          &objectSelector,
				}},
			},
		}
	)

	if webhookVariant.resourceReaderSA != "" {
		clientObjects = append(clientObjects,
			&rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{
					Name:   constants.LakomResourceReader,
					Labels: getLabels(),
				},
				Rules: []rbacv1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"secrets"},
						Verbs:     []string{"get"},
					},
				},
			})
		clientObjects = append(clientObjects,
			getRoleBindings(scope, webhookVariant.resourceReaderSA, dashboardEnabled)...)

	}

	shootResources, err := webhookVariant.registry.AddAllAndSerialize(clientObjects...)

	if err != nil {
		return nil, err
	}

	return shootResources, nil
}

func getSeedResources(
	lakomReplicas *int32,
	namespace,
	genericKubeconfigName,
	shootAccessSecretName,
	serverTLSSecretName,
	lakomConfig,
	image string,
	useOnlyImagePullSecrets,
	allowUntrustedImages,
	allowInsecureRegistries,
	topologyAwareRoutingEnabled bool,
	seedK8SVersion string,
) (map[string][]byte, error) {
	var (
		tcpProto                 = corev1.ProtocolTCP
		serverPort               = intstr.FromInt32(10250)
		metricsPort              = intstr.FromInt32(8080)
		healthPort               = intstr.FromInt32(8081)
		cacheTTL                 = time.Minute * 10
		cacheRefreshInterval     = time.Second * 30
		lakomConfigDir           = "/etc/lakom/config"
		lakomConfigConfigMapName = constants.ExtensionServiceName + "-lakom-config"
		webhookTLSCertDir        = "/etc/lakom/tls"
		registry                 = managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)
		requestMemory            = resource.MustParse("25M")
		vpaUpdateMode            = vpaautoscalingv1.UpdateModeRecreate
	)

	lakomConfigConfigMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      lakomConfigConfigMapName,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		Data: map[string]string{
			"config.yaml": lakomConfig,
		},
	}

	if err := kubernetesutils.MakeUnique(&lakomConfigConfigMap); err != nil {
		return nil, err
	}

	lakomDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ExtensionServiceName,
			Namespace: namespace,
			Labels: utils.MergeStringMaps(getLabels(), map[string]string{
				resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
			}),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             lakomReplicas,
			RevisionHistoryLimit: ptr.To[int32](2),
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
						v1beta1constants.LabelNetworkPolicyToDNS:                                                                    v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPublicNetworks:                                                         v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPrivateNetworks:                                                        v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToBlockedCIDRs:                                                           v1beta1constants.LabelNetworkPolicyAllowed,
						gardenerutils.NetworkPolicyLabel(v1beta1constants.DeploymentNameKubeAPIServer, kubeapiserverconstants.Port): v1beta1constants.LabelNetworkPolicyAllowed,
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
					AutomountServiceAccountToken: ptr.To[bool](false),
					ServiceAccountName:           constants.ExtensionServiceName,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{{
						Name:            constants.ApplicationName,
						Image:           image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							Privileged:               ptr.To(false),
						},
						Args: []string{
							"--cache-ttl=" + cacheTTL.String(),
							"--cache-refresh-interval=" + cacheRefreshInterval.String(),
							"--lakom-config-path=" + lakomConfigDir + "/config.yaml",
							"--tls-cert-dir=" + webhookTLSCertDir,
							"--health-bind-address=:" + healthPort.String(),
							"--metrics-bind-address=:" + metricsPort.String(),
							"--port=" + serverPort.String(),
							"--kubeconfig=" + gardenerutils.PathGenericKubeconfig,
							"--use-only-image-pull-secrets=" + strconv.FormatBool(useOnlyImagePullSecrets),
							"--insecure-allow-untrusted-images=" + strconv.FormatBool(allowUntrustedImages),
							"--insecure-allow-insecure-registries=" + strconv.FormatBool(allowInsecureRegistries),
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "https",
								Protocol:      tcpProto,
								ContainerPort: serverPort.IntVal,
							},
							{
								Name:          "metrics",
								Protocol:      tcpProto,
								ContainerPort: metricsPort.IntVal,
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
								corev1.ResourceMemory: requestMemory,
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "lakom-config",
								MountPath: lakomConfigDir,
								ReadOnly:  true,
							},
							{
								Name:      "lakom-server-tls",
								ReadOnly:  true,
								MountPath: webhookTLSCertDir,
							},
						},
					}},
					PriorityClassName: v1beta1constants.PriorityClassNameShootControlPlane300,
					Volumes: []corev1.Volume{
						{
							Name: "lakom-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: lakomConfigConfigMap.Name,
									},
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

	if err := gardenerutils.InjectGenericKubeconfig(lakomDeployment, genericKubeconfigName, shootAccessSecretName); err != nil {
		return nil, err
	}

	if err := references.InjectAnnotations(lakomDeployment); err != nil {
		return nil, err
	}

	lakomService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ExtensionServiceName,
			Namespace: namespace,
			Labels:    getLabels(),
			Annotations: map[string]string{
				"networking.resources.gardener.cloud/from-all-scrape-targets-allowed-ports":  `[{"protocol":"TCP","port":` + metricsPort.String() + `}]`,
				"networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports": `[{"protocol":"TCP","port":` + serverPort.String() + `}]`,
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

	version, err := semver.NewVersion(seedK8SVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to parse seed k8s version %q as semantic version: %w", seedK8SVersion, err)
	}
	gardenerutils.ReconcileTopologyAwareRoutingSettings(lakomService, topologyAwareRoutingEnabled, version)

	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ExtensionServiceName,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable:             ptr.To(intstr.FromInt32(1)),
			Selector:                   &metav1.LabelSelector{MatchLabels: getLabels()},
			UnhealthyPodEvictionPolicy: ptr.To(policyv1.AlwaysAllow),
		},
	}

	resources, err := registry.AddAllAndSerialize(
		lakomDeployment,
		pdb,
		&lakomConfigConfigMap,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ExtensionServiceName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			AutomountServiceAccountToken: ptr.To[bool](false),
		},
		lakomService,
		&vpaautoscalingv1.VerticalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ExtensionServiceName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
				ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
					ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{
						{
							ContainerName: constants.ApplicationName,
							ControlledResources: &[]corev1.ResourceName{
								corev1.ResourceMemory,
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
		&monitoringv1.ServiceMonitor{
			ObjectMeta: monitoringutils.ConfigObjectMeta(constants.ExtensionServiceName, namespace, "shoot"),
			Spec: monitoringv1.ServiceMonitorSpec{
				Selector: metav1.LabelSelector{MatchLabels: getLabels()},
				Endpoints: []monitoringv1.Endpoint{{
					Port:                 "metrics",
					MetricRelabelConfigs: monitoringutils.StandardMetricRelabelConfig("lakom.*"),
				}},
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return resources, nil
}

func getGardenVirtualResources(
	lakomReplicas *int32,
	namespace,
	genericKubeconfigName, // ← new param, caller passes clusterCtx.genericTokenKubeconfigName
	gardenAccessSecretName, // ← new param, caller passes lakomGardenAccessSecret.Secret.Name
	serverTLSSecretName,
	lakomConfig,
	image string,
	useOnlyImagePullSecrets,
	allowUntrustedImages,
	allowInsecureRegistries,
	topologyAwareRoutingEnabled bool,
	seedK8SVersion string,
) (map[string][]byte, error) {
	var (
		tcpProto                 = corev1.ProtocolTCP
		serverPort               = intstr.FromInt32(10250)
		metricsPort              = intstr.FromInt32(8080)
		healthPort               = intstr.FromInt32(8081)
		cacheTTL                 = time.Minute * 10
		cacheRefreshInterval     = time.Second * 30
		lakomConfigDir           = "/etc/lakom/config"
		lakomConfigConfigMapName = constants.VirtualGardenExtensionServiceName + "-lakom-config"
		webhookTLSCertDir        = "/etc/lakom/tls"
		registry                 = managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)
		requestMemory            = resource.MustParse("25M")
		vpaUpdateMode            = vpaautoscalingv1.UpdateModeRecreate
	)

	lakomConfigConfigMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      lakomConfigConfigMapName,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		Data: map[string]string{
			"config.yaml": lakomConfig,
		},
	}

	if err := kubernetesutils.MakeUnique(&lakomConfigConfigMap); err != nil {
		return nil, err
	}

	lakomDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.VirtualGardenExtensionServiceName,
			Namespace: namespace,
			Labels: utils.MergeStringMaps(getLabels(), map[string]string{
				resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
			}),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             lakomReplicas,
			RevisionHistoryLimit: ptr.To[int32](2),
			Selector:             &metav1.LabelSelector{MatchLabels: getGardenPodLabels(true)},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
					MaxSurge:       &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: utils.MergeStringMaps(getGardenPodLabels(true), map[string]string{
						v1beta1constants.LabelNetworkPolicyToDNS:                                                                    v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPublicNetworks:                                                         v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPrivateNetworks:                                                        v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToBlockedCIDRs:                                                           v1beta1constants.LabelNetworkPolicyAllowed,
						gardenerutils.NetworkPolicyLabel(v1beta1constants.DeploymentNameKubeAPIServer, kubeapiserverconstants.Port): v1beta1constants.LabelNetworkPolicyAllowed,
					}),
				},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
								Weight: 100,
								PodAffinityTerm: corev1.PodAffinityTerm{
									TopologyKey:   corev1.LabelHostname,
									LabelSelector: &metav1.LabelSelector{MatchLabels: getGardenPodLabels(true)},
								},
							}},
						},
					},
					AutomountServiceAccountToken: ptr.To[bool](false),
					ServiceAccountName:           constants.VirtualGardenExtensionServiceName,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{{
						Name:            constants.ApplicationName,
						Image:           image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							Privileged:               ptr.To(false),
						},
						Args: []string{
							"--cache-ttl=" + cacheTTL.String(),
							"--cache-refresh-interval=" + cacheRefreshInterval.String(),
							"--lakom-config-path=" + lakomConfigDir + "/config.yaml",
							"--tls-cert-dir=" + webhookTLSCertDir,
							"--health-bind-address=:" + healthPort.String(),
							"--metrics-bind-address=:" + metricsPort.String(),
							"--port=" + serverPort.String(),
							"--kubeconfig=" + gardenerutils.PathGenericKubeconfig,
							"--use-only-image-pull-secrets=" + strconv.FormatBool(useOnlyImagePullSecrets),
							"--insecure-allow-untrusted-images=" + strconv.FormatBool(allowUntrustedImages),
							"--insecure-allow-insecure-registries=" + strconv.FormatBool(allowInsecureRegistries),
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "https",
								Protocol:      tcpProto,
								ContainerPort: serverPort.IntVal,
							},
							{
								Name:          "metrics",
								Protocol:      tcpProto,
								ContainerPort: metricsPort.IntVal,
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
								corev1.ResourceMemory: requestMemory,
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "lakom-config",
								MountPath: lakomConfigDir,
								ReadOnly:  true,
							},
							{
								Name:      "lakom-server-tls",
								ReadOnly:  true,
								MountPath: webhookTLSCertDir,
							},
						},
					}},
					PriorityClassName: v1beta1constants.PriorityClassNameGardenSystem200,
					Volumes: []corev1.Volume{
						{
							Name: "lakom-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: lakomConfigConfigMap.Name,
									},
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
	if err := gardenerutils.InjectGenericKubeconfig(
		lakomDeployment,
		genericKubeconfigName,
		gardenAccessSecretName,
	); err != nil {
		return nil, err
	}

	lakomService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.VirtualGardenExtensionServiceName,
			Namespace: namespace,
			Labels:    getLabels(),
			Annotations: map[string]string{
				"networking.resources.gardener.cloud/from-all-scrape-targets-allowed-ports":  `[{"protocol":"TCP","port":` + metricsPort.String() + `}]`,
				"networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports": `[{"protocol":"TCP","port":` + serverPort.String() + `}]`,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: getGardenPodLabels(true),
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

	version, err := semver.NewVersion(seedK8SVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to parse seed k8s version %q as semantic version: %w", seedK8SVersion, err)
	}
	gardenerutils.ReconcileTopologyAwareRoutingSettings(lakomService, topologyAwareRoutingEnabled, version)

	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.VirtualGardenExtensionServiceName,
			Namespace: namespace,
			Labels:    getLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable:             ptr.To(intstr.FromInt32(1)),
			Selector:                   &metav1.LabelSelector{MatchLabels: getGardenPodLabels(true)},
			UnhealthyPodEvictionPolicy: ptr.To(policyv1.AlwaysAllow),
		},
	}

	resources, err := registry.AddAllAndSerialize(
		lakomDeployment,
		pdb,
		&lakomConfigConfigMap,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.VirtualGardenExtensionServiceName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			AutomountServiceAccountToken: ptr.To[bool](false),
		},
		lakomService,
		&vpaautoscalingv1.VerticalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.VirtualGardenExtensionServiceName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
				ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
					ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{
						{
							ContainerName: constants.ApplicationName,
							ControlledResources: &[]corev1.ResourceName{
								corev1.ResourceMemory,
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
		&monitoringv1.ServiceMonitor{
			ObjectMeta: monitoringutils.ConfigObjectMeta(constants.VirtualGardenExtensionServiceName, namespace, "virtual-garden"),
			Spec: monitoringv1.ServiceMonitorSpec{
				Selector: metav1.LabelSelector{MatchLabels: getGardenPodLabels(true)},
				Endpoints: []monitoringv1.Endpoint{{
					Port:                 "metrics",
					MetricRelabelConfigs: monitoringutils.StandardMetricRelabelConfig("lakom.*"),
				}},
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return resources, nil
}

func getGardenRuntimeResources(
	lakomReplicas *int32,
	serverTLSSecretName,
	lakomConfig,
	image string,
	useOnlyImagePullSecrets,
	allowUntrustedImages,
	allowInsecureRegistries,
	topologyAwareRoutingEnabled bool,
	seedK8SVersion string,
) (map[string][]byte, error) {
	var (
		tcpProto                 = corev1.ProtocolTCP
		serverPort               = intstr.FromInt32(10250)
		metricsPort              = intstr.FromInt32(8080)
		healthPort               = intstr.FromInt32(8081)
		cacheTTL                 = time.Minute * 10
		cacheRefreshInterval     = time.Second * 30
		lakomConfigDir           = "/etc/lakom/config"
		lakomConfigConfigMapName = constants.RuntimeGardenExtensionServiceName + "-lakom-config"
		webhookTLSCertDir        = "/etc/lakom/tls"
		registry                 = managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)
		requestMemory            = resource.MustParse("25M")
		vpaUpdateMode            = vpaautoscalingv1.UpdateModeRecreate
	)

	lakomConfigConfigMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      lakomConfigConfigMapName,
			Namespace: constants.LakomSystemNamespace,
			Labels:    getLabels(),
		},
		Data: map[string]string{
			"config.yaml": lakomConfig,
		},
	}

	if err := kubernetesutils.MakeUnique(&lakomConfigConfigMap); err != nil {
		return nil, err
	}

	lakomSystemNamespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: constants.LakomSystemNamespace,
			// Labels: getLabels(),
		},
	}

	lakomDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.RuntimeGardenExtensionServiceName,
			Namespace: constants.LakomSystemNamespace,
			Labels: utils.MergeStringMaps(getLabels(), map[string]string{
				resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
			}),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             lakomReplicas,
			RevisionHistoryLimit: ptr.To[int32](2),
			Selector:             &metav1.LabelSelector{MatchLabels: getGardenPodLabels(false)},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
					MaxSurge:       &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: utils.MergeStringMaps(getGardenPodLabels(false), map[string]string{
						v1beta1constants.LabelNetworkPolicyToDNS:                                                                    v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPublicNetworks:                                                         v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPrivateNetworks:                                                        v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToBlockedCIDRs:                                                           v1beta1constants.LabelNetworkPolicyAllowed,
						gardenerutils.NetworkPolicyLabel(v1beta1constants.DeploymentNameKubeAPIServer, kubeapiserverconstants.Port): v1beta1constants.LabelNetworkPolicyAllowed,
					}),
				},
				Spec: corev1.PodSpec{
					Affinity: &corev1.Affinity{
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
								Weight: 100,
								PodAffinityTerm: corev1.PodAffinityTerm{
									TopologyKey:   corev1.LabelHostname,
									LabelSelector: &metav1.LabelSelector{MatchLabels: getGardenPodLabels(false)},
								},
							}},
						},
					},
					AutomountServiceAccountToken: ptr.To[bool](true),
					ServiceAccountName:           constants.RuntimeGardenExtensionServiceName,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{{
						Name:            constants.ApplicationName,
						Image:           image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							Privileged:               ptr.To(false),
						},
						Args: []string{
							"--cache-ttl=" + cacheTTL.String(),
							"--cache-refresh-interval=" + cacheRefreshInterval.String(),
							"--lakom-config-path=" + lakomConfigDir + "/config.yaml",
							"--tls-cert-dir=" + webhookTLSCertDir,
							"--health-bind-address=:" + healthPort.String(),
							"--metrics-bind-address=:" + metricsPort.String(),
							"--port=" + serverPort.String(),
							"--use-only-image-pull-secrets=" + strconv.FormatBool(useOnlyImagePullSecrets),
							"--insecure-allow-untrusted-images=" + strconv.FormatBool(allowUntrustedImages),
							"--insecure-allow-insecure-registries=" + strconv.FormatBool(allowInsecureRegistries),
						},
						Ports: []corev1.ContainerPort{
							{
								Name:          "https",
								Protocol:      tcpProto,
								ContainerPort: serverPort.IntVal,
							},
							{
								Name:          "metrics",
								Protocol:      tcpProto,
								ContainerPort: metricsPort.IntVal,
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
								corev1.ResourceMemory: requestMemory,
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{
								Name:      "lakom-config",
								MountPath: lakomConfigDir,
								ReadOnly:  true,
							},
							{
								Name:      "lakom-server-tls",
								ReadOnly:  true,
								MountPath: webhookTLSCertDir,
							},
						},
					}},
					PriorityClassName: v1beta1constants.PriorityClassNameGardenSystem200,
					Volumes: []corev1.Volume{
						{
							Name: "lakom-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: lakomConfigConfigMap.Name,
									},
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

	lakomService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.RuntimeGardenExtensionServiceName,
			Namespace: constants.LakomSystemNamespace,
			Labels:    getLabels(),
			Annotations: map[string]string{
				"networking.resources.gardener.cloud/from-all-scrape-targets-allowed-ports":  `[{"protocol":"TCP","port":` + metricsPort.String() + `}]`,
				"networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports": `[{"protocol":"TCP","port":` + serverPort.String() + `}]`,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: getGardenPodLabels(false),
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

	version, err := semver.NewVersion(seedK8SVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to parse seed k8s version %q as semantic version: %w", seedK8SVersion, err)
	}
	gardenerutils.ReconcileTopologyAwareRoutingSettings(lakomService, topologyAwareRoutingEnabled, version)

	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.RuntimeGardenExtensionServiceName,
			Namespace: constants.LakomSystemNamespace,
			Labels:    getLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable:             ptr.To(intstr.FromInt32(1)),
			Selector:                   &metav1.LabelSelector{MatchLabels: getGardenPodLabels(false)},
			UnhealthyPodEvictionPolicy: ptr.To(policyv1.AlwaysAllow),
		},
	}

	resources, err := registry.AddAllAndSerialize(
		lakomSystemNamespace,
		lakomDeployment,
		pdb,
		&lakomConfigConfigMap,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.RuntimeGardenExtensionServiceName,
				Namespace: constants.LakomSystemNamespace,
				Labels:    getLabels(),
			},
			AutomountServiceAccountToken: ptr.To[bool](true),
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.RuntimeGardenExtensionServiceName,
				Namespace: constants.LakomSystemNamespace,
				Labels:    getLabels(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.RuntimeGardenExtensionServiceName,
				Namespace: constants.LakomSystemNamespace,
				Labels:    getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     constants.RuntimeGardenExtensionServiceName,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      constants.RuntimeGardenExtensionServiceName,
					Namespace: constants.LakomSystemNamespace,
				},
			},
		},
		lakomService,
		&vpaautoscalingv1.VerticalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.RuntimeGardenExtensionServiceName,
				Namespace: constants.LakomSystemNamespace,
				Labels:    getLabels(),
			},
			Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
				ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
					ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{
						{
							ContainerName: constants.ApplicationName,
							ControlledResources: &[]corev1.ResourceName{
								corev1.ResourceMemory,
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
		&monitoringv1.ServiceMonitor{
			ObjectMeta: monitoringutils.ConfigObjectMeta(constants.RuntimeGardenExtensionServiceName, constants.LakomSystemNamespace, "garden-runtime"),
			Spec: monitoringv1.ServiceMonitorSpec{
				Selector: metav1.LabelSelector{MatchLabels: getGardenPodLabels(false)},
				Endpoints: []monitoringv1.Endpoint{{
					Port:                 "metrics",
					MetricRelabelConfigs: monitoringutils.StandardMetricRelabelConfig("lakom.*"),
				}},
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return resources, nil
}

func getRoleBindings(scope lakom.ScopeType, shootAccessServiceAccountName string, dashboardEnabled bool) []client.Object {
	roleRef := rbacv1.RoleRef{
		APIGroup: "rbac.authorization.k8s.io",
		Kind:     "ClusterRole",
		Name:     constants.LakomResourceReader,
	}
	subjects := []rbacv1.Subject{
		{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      shootAccessServiceAccountName,
			Namespace: metav1.NamespaceSystem,
		},
	}
	annotations := map[string]string{
		resourcesv1alpha1.DeleteOnInvalidUpdate: "true",
	}

	if scope == lakom.Cluster {
		return []client.Object{&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:        constants.LakomResourceReader,
				Labels:      getLabels(),
				Annotations: annotations,
			},
			RoleRef:  roleRef,
			Subjects: subjects,
		}}
	}

	roleBindings := []client.Object{&rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:        constants.LakomResourceReader,
			Namespace:   metav1.NamespaceSystem,
			Labels:      getLabels(),
			Annotations: annotations,
		},
		RoleRef:  roleRef,
		Subjects: subjects,
	}}

	if dashboardEnabled {
		roleBindings = append(roleBindings, &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:        constants.LakomResourceReader,
				Namespace:   kubernetesDashboardNamespaceName,
				Labels:      getLabels(),
				Annotations: annotations,
			},
			RoleRef:  roleRef,
			Subjects: subjects,
		})
	}

	return roleBindings
}

type webhookVariant struct {
	registry               *managedresources.Registry
	configName             string
	resourceReaderSA       string
	useServiceClientConfig bool
}

// serviceBasedWebhookClientConfig builds a Service-based webhook client config
func serviceBasedWebhookClientConfig(caBundle []byte, namespace, serviceName, path string) admissionregistrationv1.WebhookClientConfig {
	return admissionregistrationv1.WebhookClientConfig{
		Service: &admissionregistrationv1.ServiceReference{
			Namespace: namespace,
			Name:      serviceName,
			Path:      ptr.To(path),
		},
		CABundle: caBundle,
	}
}

// urlBasedWebhookClientConfig builds a URL-based webhook client config
func urlBasedWebhookClientConfig(caBundle []byte, host, path string) admissionregistrationv1.WebhookClientConfig {
	url := fmt.Sprintf("https://%s%s", host, path)
	return admissionregistrationv1.WebhookClientConfig{
		URL:      ptr.To(url),
		CABundle: caBundle,
	}
}

func shootWebhookVariant(configName, resourceReaderSA string) webhookVariant {
	return webhookVariant{
		registry:         managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer),
		configName:       configName,
		resourceReaderSA: resourceReaderSA,
	}
}

func runtimeWebhookVariant() webhookVariant {
	return webhookVariant{
		registry:               managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer),
		configName:             constants.RuntimeWebhookConfigurationName,
		useServiceClientConfig: true,
	}
}
