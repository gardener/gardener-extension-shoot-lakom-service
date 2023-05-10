// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/imagevector"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/secrets"

	"github.com/Masterminds/semver"
	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/extensions"
	kubeapiserverconstants "github.com/gardener/gardener/pkg/operation/botanist/component/kubeapiserver/constants"
	"github.com/gardener/gardener/pkg/resourcemanager/controller/garbagecollector/references"
	"github.com/gardener/gardener/pkg/utils"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/sets"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/version"
	"k8s.io/utils/clock"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// ActuatorName is the name of the Lakom Service actuator.
	ActuatorName = constants.ExtensionType + "-actuator"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(config config.Configuration) extension.Actuator {
	return &actuator{
		serviceConfig: config,
	}
}

type actuator struct {
	client        client.Client
	config        *rest.Config
	decoder       runtime.Decoder
	serviceConfig config.Configuration
}

func getLakomReplicas(hibernated bool) *int32 {
	// Scale to 0 if cluster is hibernated
	if hibernated {
		return pointer.Int32(0)
	}

	return pointer.Int32(3)
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}

	lakomShootAccessSecret := gutil.NewShootAccessSecret(gutil.SecretNamePrefixShootAccess+constants.ApplicationName, namespace)
	lakomShootAccessSecret.Secret.SetLabels(utils.MergeStringMaps(
		getLabels(),
		lakomShootAccessSecret.Secret.GetLabels(),
	))
	if err := lakomShootAccessSecret.Reconcile(ctx, a.client); err != nil {
		return err
	}

	// initialize SecretsManager based on Cluster object
	configs := secrets.ConfigsFor(namespace)

	secretsManager, err := extensionssecretsmanager.SecretsManagerForCluster(ctx, logger.WithName("secretsmanager"), clock.RealClock{}, a.client, cluster, secrets.ManagerIdentity, configs)
	if err != nil {
		return err
	}

	generatedSecrets, err := extensionssecretsmanager.GenerateAllSecrets(ctx, secretsManager, configs)
	if err != nil {
		return err
	}

	caBundleSecret, found := secretsManager.Get(secrets.CAName)
	if !found {
		return fmt.Errorf("secret %q not found", secrets.CAName)
	}

	if cluster.Seed == nil || cluster.Seed.Status.KubernetesVersion == nil || len(*cluster.Seed.Status.KubernetesVersion) == 0 {
		return fmt.Errorf("missing or empty `cluster.seed.status.kubernetesVersion`")
	}

	seedK8SVersion, err := semver.NewVersion(*cluster.Seed.Status.KubernetesVersion)
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

	seedResources, err := getSeedResources(
		getLakomReplicas(controller.IsHibernationEnabled(cluster)),
		namespace,
		extensions.GenericTokenKubeconfigSecretNameFromCluster(cluster),
		lakomShootAccessSecret.Secret.Name,
		generatedSecrets[constants.WebhookTLSSecretName].Name,
		a.serviceConfig.CosignPublicKeys,
		image.String(),
		seedK8SVersion,
	)
	if err != nil {
		return err
	}

	var (
		failurePolicy          = admissionregistration.Fail
		allowedFailurePolicies = sets.NewString(string(admissionregistration.Fail), string(admissionregistration.Ignore))
	)

	if a.serviceConfig.FailurePolicy != nil && allowedFailurePolicies.Has(*a.serviceConfig.FailurePolicy) {
		failurePolicy = admissionregistration.FailurePolicyType(*a.serviceConfig.FailurePolicy)
	}

	shootResources, err := getShootResources(
		caBundleSecret.Data[secretutils.DataKeyCertificateBundle],
		namespace,
		lakomShootAccessSecret.ServiceAccountName,
		failurePolicy,
	)

	if err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, a.client, namespace, constants.ManagedResourceNamesSeed, false, seedResources); err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx, a.client, namespace, constants.ManagedResourceNamesShoot, constants.GardenerExtensionName, false, shootResources); err != nil {
		return err
	}

	twoMinutes := 2 * time.Minute
	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelSeedCtx()
	if err := managedresources.WaitUntilHealthy(timeoutSeedCtx, a.client, namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()
	twoMinutes := 2 * time.Minute

	timeoutShootCtx, cancelShootCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelShootCtx()

	if err := managedresources.DeleteForShoot(ctx, a.client, namespace, constants.ManagedResourceNamesShoot); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutShootCtx, a.client, namespace, constants.ManagedResourceNamesShoot); err != nil {
		return err
	}

	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelSeedCtx()

	if err := managedresources.DeleteForSeed(ctx, a.client, namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutSeedCtx, a.client, namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	if err := a.client.DeleteAllOf(ctx, &corev1.Secret{}, client.InNamespace(namespace), client.MatchingLabels(getLabels())); err != nil {
		return err
	}

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return err
	}

	secretsManager, err := extensionssecretsmanager.SecretsManagerForCluster(ctx, logger.WithName("secretsmanager"), clock.RealClock{}, a.client, cluster, secrets.ManagerIdentity, nil)
	if err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, logger, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	// Keep objects for shoot managed resources so that they are not deleted from the shoot during the migration
	if err := managedresources.SetKeepObjects(ctx, a.client, ex.GetNamespace(), constants.ManagedResourceNamesShoot, true); err != nil {
		return err
	}

	return a.Delete(ctx, logger, ex)
}

// InjectConfig injects the rest config to this actuator.
func (a *actuator) InjectConfig(config *rest.Config) error {
	a.config = config
	return nil
}

// InjectClient injects the controller runtime client into the reconciler.
func (a *actuator) InjectClient(client client.Client) error {
	a.client = client
	return nil
}

// InjectScheme injects the given scheme into the reconciler.
func (a *actuator) InjectScheme(scheme *runtime.Scheme) error {
	a.decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()
	return nil
}

func getLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":    constants.ApplicationName,
		"app.kubernetes.io/part-of": constants.ExtensionType,
	}
}

func getSeedResources(lakomReplicas *int32, namespace, genericKubeconfigName, shootAccessSecretName, serverTLSSecretName string, cosignPublicKeys []string, image string, seedK8SVersion *semver.Version) (map[string][]byte, error) {
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
	)

	cosignPublicKeysSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cosignPublicKeysSecretName,
			Namespace: namespace,
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
			Namespace: namespace,
			Labels: utils.MergeStringMaps(getLabels(), map[string]string{
				resourcesv1alpha1.HighAvailabilityConfigType: resourcesv1alpha1.HighAvailabilityConfigTypeServer,
			}),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas:             lakomReplicas,
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
						v1beta1constants.LabelNetworkPolicyToDNS:                                                            v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPublicNetworks:                                                 v1beta1constants.LabelNetworkPolicyAllowed,
						v1beta1constants.LabelNetworkPolicyToPrivateNetworks:                                                v1beta1constants.LabelNetworkPolicyAllowed,
						gutil.NetworkPolicyLabel(v1beta1constants.DeploymentNameKubeAPIServer, kubeapiserverconstants.Port): v1beta1constants.LabelNetworkPolicyAllowed,
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
					AutomountServiceAccountToken: pointer.Bool(false),
					ServiceAccountName:           constants.ExtensionServiceName,
					Containers: []corev1.Container{{
						Name:            constants.ApplicationName,
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
							"--kubeconfig=" + gutil.PathGenericKubeconfig,
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
					PriorityClassName: v1beta1constants.PriorityClassNameShootControlPlane300,
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

	if err := gutil.InjectGenericKubeconfig(lakomDeployment, genericKubeconfigName, shootAccessSecretName); err != nil {
		return nil, err
	}

	if err := references.InjectAnnotations(lakomDeployment); err != nil {
		return nil, err
	}

	lakomPDB, err := getPDB(lakomReplicas, namespace, seedK8SVersion)
	if err != nil {
		return nil, err
	}

	lakomService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ExtensionServiceName,
			Namespace: namespace,
			Labels:    getLabels(),
			Annotations: map[string]string{
				"networking.resources.gardener.cloud/from-all-scrape-targets-allowed-ports": `[{"protocol":"TCP","port":` + metricsPort.String() + `}]`,
				// TODO: This label approach is deprecated and no longer needed in the future. Remove them as soon as gardener/gardener@v1.75 has been released.
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

	resources, err := registry.AddAllAndSerialize(
		lakomDeployment,
		lakomPDB,
		&cosignPublicKeysSecret,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ExtensionServiceName,
				Namespace: namespace,
				Labels:    getLabels(),
			},
			AutomountServiceAccountToken: pointer.Bool(false),
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
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ExtensionServiceName + "-monitoring",
				Namespace: namespace,
				Labels:    utils.MergeStringMaps(getLabels(), map[string]string{v1beta1constants.LabelExtensionConfiguration: v1beta1constants.LabelMonitoring}),
			},
			Data: map[string]string{
				v1beta1constants.PrometheusConfigMapScrapeConfig: `- job_name: ` + constants.ExtensionServiceName + `
  honor_labels: false
  kubernetes_sd_configs:
  - role: endpoints
    namespaces:
      names: [` + namespace + `]
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
	)

	if err != nil {
		return nil, err
	}

	return resources, nil
}

func getPDB(replicas *int32, namespaceName string, k8sVersion *semver.Version) (client.Object, error) {

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

func getShootResources(webhookCaBundle []byte, namespace, shootAccessServiceAccountName string, failurePolicy admissionregistration.FailurePolicyType) (map[string][]byte, error) {
	var (
		matchPolicy          = admissionregistration.Equivalent
		sideEffectClass      = admissionregistration.SideEffectClassNone
		timeOutSeconds       = pointer.Int32(25)
		webhookHost          = fmt.Sprintf("https://%s.%s", constants.ExtensionServiceName, namespace)
		validatingWebhookURL = webhookHost + constants.LakomVerifyCosignSignaturePath
		mutatingWebhookURL   = webhookHost + constants.LakomResolveTagPath
		namespaceSelector    = metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      corev1.LabelMetadataName,
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{metav1.NamespaceSystem},
				},
			},
		}
		objectSelector = metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      resourcesv1alpha1.ManagedBy,
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"gardener"},
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
	)

	shootRegistry := managedresources.NewRegistry(kubernetes.ShootScheme, kubernetes.ShootCodec, kubernetes.ShootSerializer)
	shootResources, err := shootRegistry.AddAllAndSerialize(
		&admissionregistration.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:   constants.WebhookConfigurationName,
				Labels: utils.MergeStringMaps(getLabels(), map[string]string{v1beta1constants.LabelExcludeWebhookFromRemediation: "true"}),
			},
			Webhooks: []admissionregistration.MutatingWebhook{{
				Name:                    "resolve-tag.lakom.service.extensions.gardener.cloud",
				Rules:                   rules,
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				SideEffects:             &sideEffectClass,
				TimeoutSeconds:          timeOutSeconds,
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admissionregistration.WebhookClientConfig{
					URL:      &mutatingWebhookURL,
					CABundle: webhookCaBundle,
				},
				NamespaceSelector: &namespaceSelector,
				ObjectSelector:    &objectSelector,
			}},
		},
		&admissionregistration.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name:   constants.WebhookConfigurationName,
				Labels: utils.MergeStringMaps(getLabels(), map[string]string{v1beta1constants.LabelExcludeWebhookFromRemediation: "true"}),
			},
			Webhooks: []admissionregistration.ValidatingWebhook{{
				Name:                    "verify-signature.lakom.service.extensions.gardener.cloud",
				Rules:                   rules,
				FailurePolicy:           &failurePolicy,
				MatchPolicy:             &matchPolicy,
				SideEffects:             &sideEffectClass,
				TimeoutSeconds:          timeOutSeconds,
				AdmissionReviewVersions: []string{"v1"},
				ClientConfig: admissionregistration.WebhookClientConfig{
					URL:      &validatingWebhookURL,
					CABundle: webhookCaBundle,
				},
				NamespaceSelector: &namespaceSelector,
				ObjectSelector:    &objectSelector,
			}},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.LakomResourceReader,
				Namespace: metav1.NamespaceSystem,
				Labels:    getLabels(),
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get"},
				},
			},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.LakomResourceReader,
				Namespace: metav1.NamespaceSystem,
				Labels:    getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     constants.LakomResourceReader,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      shootAccessServiceAccountName,
					Namespace: metav1.NamespaceSystem,
				},
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return shootResources, nil
}
