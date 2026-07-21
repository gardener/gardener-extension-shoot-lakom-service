// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

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

	gardenRuntimeWebhookRules []admissionregistrationv1.RuleWithOperations = []admissionregistrationv1.RuleWithOperations{
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

	gardenVirtualWebhookRules []admissionregistrationv1.RuleWithOperations = []admissionregistrationv1.RuleWithOperations{
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
	webhookOptions webhookOptions,
	webhookRRules []admissionregistrationv1.RuleWithOperations,
	serviceName,
	extensionNamespace string,
) (map[string][]byte, error) {
	clientConfigFor := func(path string) admissionregistrationv1.WebhookClientConfig {
		return getWebhookClientConfig(webhookOptions.useServiceClientConfig, webhookOptions.caBundle, extensionNamespace, serviceName, path)
	}

	var (
		matchPolicy       = admissionregistrationv1.Equivalent
		sideEffectClass   = admissionregistrationv1.SideEffectClassNone
		failurePolicy     = admissionregistrationv1.Fail
		timeOutSeconds    = ptr.To[int32](25)
		namespaceSelector = webhookOptions.namespaceSelector
		objectSelector    = webhookOptions.objectSelector
		resources         = []client.Object{
			&admissionregistrationv1.MutatingWebhookConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name:   webhookOptions.configName,
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
					Name:   webhookOptions.configName,
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

	if webhookOptions.resourceReaderSvcAccName != "" {
		resources = append(resources,
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
		resources = append(resources,
			getRoleBindings(webhookOptions.scope, webhookOptions.resourceReaderSvcAccName, webhookOptions.dashboardEnabled)...)

	}

	return webhookOptions.registry.AddAllAndSerialize(resources...)
}

// lakomResourceOptions parameterizes getLakomResources across deployment flavours.
type lakomResourceOptions struct {
	replicas                    *int32
	serverTLSSecretName         string
	lakomPublicKeysConfig       string
	image                       string
	useOnlyImagePullSecrets     bool
	allowUntrustedImages        bool
	allowInsecureRegistries     bool
	topologyAwareRoutingEnabled bool
	k8sVersion                  string

	serviceName           string
	namespace             string
	podLabels             map[string]string
	priorityClassName     string
	serviceMonitorSuffix  string
	useInClusterAuth      bool
	genericKubeconfigName string
	accessSecretName      string
	createInClusterRBAC   bool
}

// getLakomResources builds the full lakom workload for a single flavour and
// returns the serialized ManagedResource data.
func getLakomResources(opts lakomResourceOptions) (map[string][]byte, error) {
	var (
		tcpProto                 = corev1.ProtocolTCP
		serverPort               = intstr.FromInt32(10250)
		metricsPort              = intstr.FromInt32(8080)
		healthPort               = intstr.FromInt32(8081)
		cacheTTL                 = time.Minute * 10
		cacheRefreshInterval     = time.Second * 30
		lakomConfigDir           = "/etc/lakom/config"
		lakomConfigConfigMapName = opts.serviceName + "-lakom-config"
		webhookTLSCertDir        = "/etc/lakom/tls"
		registry                 = managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)
		requestMemory            = resource.MustParse("25M")
		vpaUpdateMode            = vpaautoscalingv1.UpdateModeInPlaceOrRecreate
	)

	lakomConfigConfigMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      lakomConfigConfigMapName,
			Namespace: opts.namespace,
			Labels:    getLabels(),
		},
		Data: map[string]string{
			"config.yaml": opts.lakomPublicKeysConfig,
		},
	}

	if err := kubernetesutils.MakeUnique(&lakomConfigConfigMap); err != nil {
		return nil, err
	}

	args := []string{
		"--cache-ttl=" + cacheTTL.String(),
		"--cache-refresh-interval=" + cacheRefreshInterval.String(),
		"--lakom-config-path=" + lakomConfigDir + "/config.yaml",
		"--tls-cert-dir=" + webhookTLSCertDir,
		"--health-bind-address=:" + healthPort.String(),
		"--metrics-bind-address=:" + metricsPort.String(),
		"--port=" + serverPort.String(),
		"--use-only-image-pull-secrets=" + strconv.FormatBool(opts.useOnlyImagePullSecrets),
		"--insecure-allow-untrusted-images=" + strconv.FormatBool(opts.allowUntrustedImages),
		"--insecure-allow-insecure-registries=" + strconv.FormatBool(opts.allowInsecureRegistries),
	}
	if !opts.useInClusterAuth {
		args = append(args, "--kubeconfig="+gardenerutils.PathGenericKubeconfig)
	}

	lakomDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.serviceName,
			Namespace: opts.namespace,
			Labels: utils.MergeStringMaps(getLabels(), map[string]string{
				resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
			}),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             opts.replicas,
			RevisionHistoryLimit: ptr.To[int32](2),
			Selector:             &metav1.LabelSelector{MatchLabels: opts.podLabels},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RollingUpdateDeploymentStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDeployment{
					MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 0},
					MaxSurge:       &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: utils.MergeStringMaps(opts.podLabels, map[string]string{
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
									LabelSelector: &metav1.LabelSelector{MatchLabels: opts.podLabels},
								},
							}},
						},
					},
					AutomountServiceAccountToken: &opts.useInClusterAuth,
					ServiceAccountName:           opts.serviceName,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{{
						Name:            constants.ApplicationName,
						Image:           opts.image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							Privileged:               ptr.To(false),
						},
						Args: args,
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
					PriorityClassName: opts.priorityClassName,
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
									SecretName: opts.serverTLSSecretName,
								},
							},
						},
					},
				},
			},
		},
	}
	lakomDeployment.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("Deployment"))

	if !opts.useInClusterAuth {
		if err := gardenerutils.InjectGenericKubeconfig(lakomDeployment, opts.genericKubeconfigName, opts.accessSecretName); err != nil {
			return nil, err
		}
	}

	if err := references.InjectAnnotations(lakomDeployment); err != nil {
		return nil, err
	}

	lakomService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.serviceName,
			Namespace: opts.namespace,
			Labels:    getLabels(),
			Annotations: map[string]string{
				"networking.resources.gardener.cloud/from-all-scrape-targets-allowed-ports":  `[{"protocol":"TCP","port":` + metricsPort.String() + `}]`,
				"networking.resources.gardener.cloud/from-all-webhook-targets-allowed-ports": `[{"protocol":"TCP","port":` + serverPort.String() + `}]`,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: opts.podLabels,
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

	version, err := semver.NewVersion(opts.k8sVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to parse k8s version %q as semantic version: %w", opts.k8sVersion, err)
	}
	gardenerutils.ReconcileTopologyAwareRoutingSettings(lakomService, opts.topologyAwareRoutingEnabled, version)

	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.serviceName,
			Namespace: opts.namespace,
			Labels:    getLabels(),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable:             ptr.To(intstr.FromInt32(1)),
			Selector:                   &metav1.LabelSelector{MatchLabels: opts.podLabels},
			UnhealthyPodEvictionPolicy: ptr.To(policyv1.AlwaysAllow),
		},
	}

	resources := []client.Object{}
	resources = append(resources,
		lakomDeployment,
		pdb,
		&lakomConfigConfigMap,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      opts.serviceName,
				Namespace: opts.namespace,
				Labels:    getLabels(),
			},
			AutomountServiceAccountToken: &opts.useInClusterAuth,
		},
	)
	if opts.createInClusterRBAC {
		resources = append(resources,
			&rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      opts.serviceName,
					Namespace: opts.namespace,
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
					Name:      opts.serviceName,
					Namespace: opts.namespace,
					Labels:    getLabels(),
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     opts.serviceName,
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      rbacv1.ServiceAccountKind,
						Name:      opts.serviceName,
						Namespace: opts.namespace,
					},
				},
			},
		)
	}
	resources = append(resources,
		lakomService,
		&vpaautoscalingv1.VerticalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      opts.serviceName,
				Namespace: opts.namespace,
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
			ObjectMeta: monitoringutils.ConfigObjectMeta(opts.serviceName, opts.namespace, opts.serviceMonitorSuffix),
			Spec: monitoringv1.ServiceMonitorSpec{
				Selector: metav1.LabelSelector{MatchLabels: opts.podLabels},
				Endpoints: []monitoringv1.Endpoint{{
					Port:                 "metrics",
					MetricRelabelConfigs: monitoringutils.StandardMetricRelabelConfig("lakom.*"),
				}},
			},
		},
	)

	return registry.AddAllAndSerialize(resources...)
}

func getSeedResources(
	clusterCtx *clusterContext,
	lakomReplicas *int32,
	serviceName,
	shootAccessSecretName,
	serverTLSSecretName string,
	useOnlyImagePullSecrets,
	allowUntrustedImages,
	allowInsecureRegistries bool,
) (map[string][]byte, error) {
	return getLakomResources(lakomResourceOptions{
		replicas:                    lakomReplicas,
		serverTLSSecretName:         serverTLSSecretName,
		lakomPublicKeysConfig:       string(clusterCtx.lakomPublicKeysConfig),
		image:                       clusterCtx.image,
		useOnlyImagePullSecrets:     useOnlyImagePullSecrets,
		allowUntrustedImages:        allowUntrustedImages,
		allowInsecureRegistries:     allowInsecureRegistries,
		topologyAwareRoutingEnabled: clusterCtx.topologyAwareRoutingEnabled,
		k8sVersion:                  clusterCtx.kubernetesVersion,
		serviceName:                 serviceName,
		namespace:                   clusterCtx.namespace,
		podLabels:                   getLabels(),
		priorityClassName:           v1beta1constants.PriorityClassNameShootControlPlane300,
		serviceMonitorSuffix:        "shoot",
		genericKubeconfigName:       clusterCtx.genericTokenKubeconfigName,
		accessSecretName:            shootAccessSecretName,
	})
}

func getGardenVirtualResources(
	clusterCtx *clusterContext,
	lakomReplicas *int32,
	accessSecretName string,
	useOnlyImagePullSecrets,
	allowUntrustedImages,
	allowInsecureRegistries bool,
) (map[string][]byte, error) {
	return getLakomResources(lakomResourceOptions{
		replicas:                    lakomReplicas,
		serverTLSSecretName:         clusterCtx.generatedSecrets[constants.GardenVirtualWebhookTLSSecretName].Name,
		lakomPublicKeysConfig:       string(clusterCtx.lakomPublicKeysConfig),
		image:                       clusterCtx.image,
		useOnlyImagePullSecrets:     useOnlyImagePullSecrets,
		allowUntrustedImages:        allowUntrustedImages,
		allowInsecureRegistries:     allowInsecureRegistries,
		topologyAwareRoutingEnabled: clusterCtx.topologyAwareRoutingEnabled,
		k8sVersion:                  clusterCtx.kubernetesVersion,
		serviceName:                 constants.GardenVirtualExtensionServiceName,
		namespace:                   clusterCtx.namespace,
		podLabels:                   getGardenPodLabels(true),
		priorityClassName:           v1beta1constants.PriorityClassNameGardenSystem200,
		serviceMonitorSuffix:        "garden-virtual",
		genericKubeconfigName:       clusterCtx.genericTokenKubeconfigName,
		accessSecretName:            accessSecretName,
	})
}

func getGardenRuntimeResources(
	clusterCtx *clusterContext,
	lakomReplicas *int32,
	serverTLSSecretName string,
	useOnlyImagePullSecrets,
	allowUntrustedImages,
	allowInsecureRegistries bool,
) (map[string][]byte, error) {
	return getLakomResources(lakomResourceOptions{
		replicas:                    lakomReplicas,
		serverTLSSecretName:         serverTLSSecretName,
		lakomPublicKeysConfig:       string(clusterCtx.lakomPublicKeysConfig),
		image:                       clusterCtx.image,
		useOnlyImagePullSecrets:     useOnlyImagePullSecrets,
		allowUntrustedImages:        allowUntrustedImages,
		allowInsecureRegistries:     allowInsecureRegistries,
		topologyAwareRoutingEnabled: clusterCtx.topologyAwareRoutingEnabled,
		k8sVersion:                  clusterCtx.kubernetesVersion,
		serviceName:                 constants.GardenRuntimeExtensionServiceName,
		namespace:                   constants.LakomSystemNamespaceName,
		podLabels:                   getGardenPodLabels(false),
		priorityClassName:           v1beta1constants.PriorityClassNameGardenSystem200,
		serviceMonitorSuffix:        "garden-runtime",
		useInClusterAuth:            true,
		createInClusterRBAC:         true,
	})
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

type webhookOptions struct {
	registry                 *managedresources.Registry
	caBundle                 []byte
	configName               string
	resourceReaderSvcAccName string
	useServiceClientConfig   bool
	namespaceSelector        metav1.LabelSelector
	objectSelector           metav1.LabelSelector
	scope                    lakom.ScopeType
	dashboardEnabled         bool
}

func shootWebhookOptions(configName, resourceReaderSvcAccName string, scope lakom.ScopeType, dashboardEnabled bool, caBundle []byte) webhookOptions {
	return webhookOptions{
		registry:                 managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer),
		caBundle:                 caBundle,
		configName:               configName,
		resourceReaderSvcAccName: resourceReaderSvcAccName,
		namespaceSelector:        scopeToNamespaceSelector(scope, dashboardEnabled),
		objectSelector:           scopeToObjectSelector(scope),
		scope:                    scope,
		dashboardEnabled:         dashboardEnabled,
	}
}

func gardenRuntimeWebhookOptions(caBundle []byte) webhookOptions {
	return webhookOptions{
		registry:               managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer),
		caBundle:               caBundle,
		configName:             constants.GardenRuntimeWebhookConfigurationName,
		useServiceClientConfig: true,
		namespaceSelector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      corev1.LabelMetadataName,
				Operator: metav1.LabelSelectorOpNotIn,
				Values: []string{
					constants.LakomSystemNamespaceName,
					metav1.NamespaceSystem,
				},
			},
		}},
	}
}

func gardenVirtualWebhookOptions(resourceReaderSvcAccName string, caBundle []byte) webhookOptions {
	return webhookOptions{
		registry:                 managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer),
		caBundle:                 caBundle,
		configName:               constants.GardenVirtualWebhookConfigurationName,
		resourceReaderSvcAccName: resourceReaderSvcAccName,
	}
}

// getClientConfig builds a webhook client config
func getWebhookClientConfig(useServiceClientConfig bool, caBundle []byte, namespace, serviceName, path string) admissionregistrationv1.WebhookClientConfig {
	if useServiceClientConfig {
		return admissionregistrationv1.WebhookClientConfig{
			Service: &admissionregistrationv1.ServiceReference{
				Namespace: namespace,
				Name:      serviceName,
				Path:      &path,
			},
			CABundle: caBundle,
		}
	}

	url := fmt.Sprintf("https://%s.%s%s", serviceName, namespace, path)
	return admissionregistrationv1.WebhookClientConfig{
		URL:      &url,
		CABundle: caBundle,
	}
}

func scopeToObjectSelector(scope lakom.ScopeType) metav1.LabelSelector {
	if scope == lakom.KubeSystemManagedByGardener {
		return metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      resourcesv1alpha1.ManagedBy,
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"gardener"},
			},
		}}
	}

	return metav1.LabelSelector{}
}

func scopeToNamespaceSelector(scope lakom.ScopeType, dashboardEnabled bool) metav1.LabelSelector {
	if scope == lakom.Cluster {
		return metav1.LabelSelector{}
	}

	namespaces := []string{metav1.NamespaceSystem}
	if dashboardEnabled {
		// TODO(vpnachev): Remove after support for shoots using kubernetes version <v1.35.0 is dropped,
		// i.e. the support for the kubernetes dashboard addon is removed.
		namespaces = append(namespaces, kubernetesDashboardNamespaceName)
	}

	return metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
		{
			Key:      corev1.LabelMetadataName,
			Operator: metav1.LabelSelectorOpIn,
			Values:   namespaces,
		},
	}}
}
