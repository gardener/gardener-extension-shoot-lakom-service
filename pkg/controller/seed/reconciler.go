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
	client        client.Client
	serviceConfig config.Configuration
}

// Reconcile installs the lakom admission controller in the kube-system namespace.
func (kcr *kubeSystemReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info(`"kube-system" namespace reconciliation starting`)

	ns := corev1.Namespace{}
	if err := kcr.client.Get(ctx, request.NamespacedName, &ns); err != nil {
		logger.Error(err, "failed to get namespace", "namespace", request.NamespacedName)
		return reconcile.Result{Requeue: true}, err
	}

	if ns.Name != metav1.NamespaceSystem {
		logger.Info(`namespace name is not "kube-system", skipping reconciliation`, "namespace", ns)
		return reconcile.Result{}, nil
	}

	if err := kcr.reconcile(ctx, logger); err != nil {
		logger.Error(err, `"kube-system" namespace reconciliation failed`)
		return reconcile.Result{Requeue: true}, err
	}

	logger.Info(`"kube-system" namespace reconciliation succeeded`)
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
	caBundleSecret, found := secretsManager.Get(CAName, secretsmanager.Bundle)
	if !found {
		return fmt.Errorf("secret %q not found", CAName)
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
		generatedSecrets[constants.SeedWebhookTLSSecretName].Name,
		image.String(),
		kcr.serviceConfig.CosignPublicKeys,
		caBundleSecret.Data[secretutils.DataKeyCertificateBundle],
		failurePolicy,
	)
	if err != nil {
		return err
	}

	var (
		ownerNamespace = kcr.serviceConfig.SeedBootstrap.OwnerNamespace
	)

	if err := managedresources.CreateForSeed(ctx, kcr.client, ownerNamespace, constants.ManagedResourceNamesSeed, false, resources); err != nil {
		return err
	}

	twoMinutes := 2 * time.Minute
	timeoutHealthCtx, cancelHealthCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelHealthCtx()
	if err := managedresources.WaitUntilHealthy(timeoutHealthCtx, kcr.client, ownerNamespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	if err := secretsManager.Cleanup(ctx); err != nil {
		return err
	}

	if err := kcr.setOwnerReferenceToSecrets(ctx, ownerNamespace); err != nil {
		return err
	}

	// TODO(vpnachev): Remove the clean up secret manager in a future version of the extension.
	legacySecretManager, err := secretsmanager.New(ctx, logger.WithName("legacy-seed-secretsmanager"), clock.RealClock{}, kcr.client, ownerNamespace, "gardener-extension-shoot-lakom-service-seed-webhook", secretsmanager.Config{})
	if err != nil {
		return fmt.Errorf("failed to create legacy secret manager in namespace: %q, err: %w", ownerNamespace, err)
	}

	return legacySecretManager.Cleanup(ctx)
}

func getLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":    constants.SeedApplicationName,
		"app.kubernetes.io/part-of": constants.ExtensionType,
	}
}

func (kcr *kubeSystemReconciler) setOwnerReferenceToSecrets(ctx context.Context, ownerNamespaceName string) error {
	secretList := &corev1.SecretList{}
	if err := kcr.client.List(ctx, secretList, client.InNamespace(metav1.NamespaceSystem), client.MatchingLabels{
		secretsmanager.LabelKeyManagedBy:       secretsmanager.LabelValueSecretsManager,
		secretsmanager.LabelKeyManagerIdentity: ManagerIdentity,
	}); err != nil {
		return err
	}

	owner := corev1.Namespace{}
	if err := kcr.client.Get(ctx, client.ObjectKey{Name: ownerNamespaceName}, &owner); err != nil {
		return err
	}

	ownerRef := metav1.NewControllerRef(&owner, corev1.SchemeGroupVersion.WithKind("Namespace"))
	ownerRef.BlockOwnerDeletion = pointer.Bool(false)

	for _, s := range secretList.Items {
		secret := s.DeepCopy()
		patch := client.StrategicMergeFrom(secret.DeepCopy(), client.MergeFromWithOptimisticLock{})
		secret.SetOwnerReferences(kutil.MergeOwnerReferences(secret.GetOwnerReferences(), *ownerRef))
		if err := kcr.client.Patch(ctx, secret, patch); err != nil {
			return err
		}
	}

	return nil
}

func getResources(serverTLSSecretName, image string, cosignPublicKeys []string, webhookCaBundle []byte, failurePolicy admissionregistration.FailurePolicyType) (map[string][]byte, error) {
	var (
		tcpProto                   = corev1.ProtocolTCP
		serverPort                 = intstr.FromInt(10250)
		metricsPort                = intstr.FromInt(8080)
		healthPort                 = intstr.FromInt(8081)
		cacheTTL                   = time.Minute * 10
		cacheRefreshInterval       = time.Second * 30
		cosignPublicKeysDir        = "/etc/lakom/cosign"
		cosignPublicKeysSecretName = constants.SeedExtensionServiceName + "-cosign-public-keys"
		webhookTLSCertDir          = "/etc/lakom/tls"
		registry                   = managedresources.NewRegistry(kubernetes.SeedScheme, kubernetes.SeedCodec, kubernetes.SeedSerializer)
		requestCPU                 = resource.MustParse("50m")
		requestMemory              = resource.MustParse("64Mi")
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
			Name:      constants.SeedExtensionServiceName,
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
						v1beta1constants.LabelNetworkPolicyToBlockedCIDRs:     v1beta1constants.LabelNetworkPolicyAllowed,
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
					ServiceAccountName:           constants.SeedExtensionServiceName,
					AutomountServiceAccountToken: pointer.Bool(true),
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

	lakomService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.SeedExtensionServiceName,
			Namespace: kubeSystemNamespace,
			Labels:    getLabels(),
			Annotations: map[string]string{
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

	resources, err := registry.AddAllAndSerialize(
		lakomDeployment,
		&policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.SeedExtensionServiceName,
				Namespace: kubeSystemNamespace,
				Labels:    getLabels(),
			},
			Spec: policyv1.PodDisruptionBudgetSpec{
				MaxUnavailable: &intstr.IntOrString{Type: intstr.Int, IntVal: 1},
				Selector:       &metav1.LabelSelector{MatchLabels: getLabels()},
			},
		},
		&cosignPublicKeysSecret,
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.SeedExtensionServiceName,
				Namespace: kubeSystemNamespace,
				Labels:    getLabels(),
			},
			AutomountServiceAccountToken: pointer.Bool(false),
		},
		lakomService,
		&vpaautoscalingv1.VerticalPodAutoscaler{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.SeedExtensionServiceName,
				Namespace: kubeSystemNamespace,
				Labels:    getLabels(),
			},
			Spec: vpaautoscalingv1.VerticalPodAutoscalerSpec{
				ResourcePolicy: &vpaautoscalingv1.PodResourcePolicy{
					ContainerPolicies: []vpaautoscalingv1.ContainerResourcePolicy{
						{
							ContainerName: constants.SeedApplicationName,
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
						Name:      constants.SeedExtensionServiceName,
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
						Name:      constants.SeedExtensionServiceName,
						Path:      pointer.String(constants.LakomVerifyCosignSignaturePath),
					},
					CABundle: webhookCaBundle,
				},
				NamespaceSelector: &namespaceSelector,
			}},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   constants.SeedExtensionServiceName,
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
				Name:   constants.SeedExtensionServiceName,
				Labels: getLabels(),
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     constants.SeedExtensionServiceName,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      rbacv1.ServiceAccountKind,
					Name:      constants.SeedExtensionServiceName,
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
