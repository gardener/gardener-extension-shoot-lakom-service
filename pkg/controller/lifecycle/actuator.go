// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/imagevector"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/secrets"

	"github.com/Masterminds/semver/v3"
	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	v1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/api/extensions/v1alpha1/helper"
	operatorv1alpha1helper "github.com/gardener/gardener/pkg/api/operator/v1alpha1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	"github.com/gardener/gardener/pkg/utils"
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/version"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/yaml"
)

const (
	// ActuatorName is the name of the Lakom Service actuator.
	ActuatorName = constants.ExtensionType + "-actuator"

	kubernetesDashboardNamespaceName = "kubernetes-dashboard"

	// virtualGardenPrefix is the prefix for virtual garden deployments
	virtualGardenPrefix = "virtual-garden-"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(mgr manager.Manager, config config.Configuration) extension.Actuator {
	return &actuator{
		client:        mgr.GetClient(),
		config:        mgr.GetConfig(),
		decoder:       serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		serviceConfig: config,
	}
}

type actuator struct {
	client        client.Client
	config        *rest.Config
	decoder       runtime.Decoder
	serviceConfig config.Configuration
}

func getScope(defaultScope lakom.ScopeType) *lakom.ScopeType {
	if defaultScope != "" {
		return ptr.To(defaultScope)
	}

	return ptr.To(lakom.KubeSystemManagedByGardener)
}

func getLakomReplicas(hibernated bool) *int32 {
	// Scale to 0 if cluster is hibernated
	if hibernated {
		return ptr.To[int32](0)
	}

	return ptr.To[int32](3)
}

// Reconcile the Extension resource
func (a *actuator) Reconcile(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	extensionClass := extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.GetExtensionClass())

	logger.Info("!!!!!!!! Reconciling Extension resource", "extensionClass", extensionClass)
	switch extensionClass {
	case extensionsv1alpha1.ExtensionClassShoot:
		return a.reconcileShoot(ctx, logger, ex)
	case extensionsv1alpha1.ExtensionClassGarden:
		return a.reconcileGarden(ctx, logger, ex)
	default:
		return fmt.Errorf("unsupported extension class: %s", extensionClass)
	}
}

func (a *actuator) reconcileShoot(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	clusterCtx, err := a.buildShootClusterContext(ctx, logger, ex)
	if err != nil {
		return err
	}

	lakomShootAccessSecret := gardenerutils.NewShootAccessSecret(
		gardenerutils.SecretNamePrefixShootAccess+constants.ApplicationName,
		clusterCtx.namespace,
	)
	lakomShootAccessSecret.Secret.SetLabels(utils.MergeStringMaps(
		getLabels(),
		lakomShootAccessSecret.Secret.GetLabels(),
	))
	if err := lakomShootAccessSecret.Reconcile(ctx, a.client); err != nil {
		return err
	}

	generatedSecrets, caBundle, lakomPublicKeys, image, lakomProviderConfig, err := a.prepareAssets(
		ctx,
		logger,
		ex,
		clusterCtx,
		secrets.ConfigsFor(clusterCtx.namespace),
		true,
	)
	if err != nil {
		return err
	}

	seedResources, err := getSeedResources(
		getLakomReplicas(clusterCtx.hibernated),
		clusterCtx.namespace,
		clusterCtx.genericTokenKubeconfigName,
		lakomShootAccessSecret.Secret.Name,
		generatedSecrets[constants.WebhookTLSSecretName].Name,
		string(lakomPublicKeys),
		image,
		a.serviceConfig.UseOnlyImagePullSecrets,
		a.serviceConfig.AllowUntrustedImages,
		a.serviceConfig.AllowInsecureRegistries,
		clusterCtx.topologyAwareRoutingEnabled,
		clusterCtx.kubernetesVersion,
	)
	if err != nil {
		return err
	}

	shootResources, err := getWebhookResources(
		caBundle,
		shootWebhookRules,
		constants.ExtensionServiceName,
		clusterCtx.namespace,
		lakomShootAccessSecret.ServiceAccountName,
		*lakomProviderConfig.Scope,
		clusterCtx.dashboardEnabled,
	)
	if err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesSeed, false, seedResources); err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesShoot, constants.GardenerExtensionName, false, shootResources); err != nil {
		return err
	}

	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelSeedCtx()
	if err := managedresources.WaitUntilHealthy(timeoutSeedCtx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	return clusterCtx.secretsManager.Cleanup(ctx)
}

func (a *actuator) reconcileGarden(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	clusterCtx, err := a.buildGardenClusterContext(ctx, logger, ex)
	if err != nil {
		return err
	}

	gardenAccessSecret := gardenerutils.NewGardenAccessSecret(
		gardenerutils.SecretNamePrefixShootAccess+constants.ApplicationName,
		clusterCtx.namespace,
	)
	gardenAccessSecret.Secret.SetLabels(utils.MergeStringMaps(getLabels(), gardenAccessSecret.Secret.GetLabels()))
	if err := gardenAccessSecret.Reconcile(ctx, a.client); err != nil {
		return err
	}

	secretConfigs := append(
		secrets.ConfigsFor(clusterCtx.namespace),
		secrets.ConfigsForVirtualGarden(clusterCtx.namespace)[1:]...,
	)

	generatedSecrets, caBundle, lakomPublicKeys, image, lakomProviderConfig, err := a.prepareAssets(
		ctx,
		logger,
		ex,
		clusterCtx,
		secretConfigs,
		false,
	)
	if err != nil {
		return err
	}

	runtimeResources, err := getGardenRuntimeResources(
		getLakomReplicas(false),
		clusterCtx.namespace,
		generatedSecrets[constants.WebhookTLSSecretName].Name,
		string(lakomPublicKeys),
		image,
		a.serviceConfig.UseOnlyImagePullSecrets,
		a.serviceConfig.AllowUntrustedImages,
		a.serviceConfig.AllowInsecureRegistries,
		clusterCtx.topologyAwareRoutingEnabled,
		clusterCtx.kubernetesVersion,
	)
	if err != nil {
		return err
	}

	virtualResources, err := getGardenVirtualResources(
		getLakomReplicas(false),
		clusterCtx.namespace,
		clusterCtx.genericTokenKubeconfigName,
		gardenAccessSecret.Secret.Name,
		generatedSecrets[constants.VirtualGardenWebhookTLSSecretName].Name,
		string(lakomPublicKeys),
		image,
		a.serviceConfig.UseOnlyImagePullSecrets,
		a.serviceConfig.AllowUntrustedImages,
		a.serviceConfig.AllowInsecureRegistries,
		clusterCtx.topologyAwareRoutingEnabled,
		clusterCtx.kubernetesVersion,
	)
	if err != nil {
		return err
	}

	gardenWebhookConfigResources, err := getWebhookResources(
		caBundle,
		gardenWebhookVirtualGardenRules,
		constants.VirtualGardenExtensionServiceName,
		clusterCtx.namespace,
		gardenAccessSecret.ServiceAccountName,
		*lakomProviderConfig.Scope,
		clusterCtx.dashboardEnabled,
	)
	if err != nil {
		return err
	}

	runtimeWebhookConfigResources, err := getWebhookResources(
		caBundle,
		gardenWebhookRuntimeRules,
		constants.ExtensionServiceName,
		clusterCtx.namespace,
		gardenAccessSecret.ServiceAccountName,
		*lakomProviderConfig.Scope,
		clusterCtx.dashboardEnabled,
	)
	if err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesGardenRuntime, false, runtimeResources); err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesGardenVirtual, false, virtualResources); err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesShoot, constants.GardenerExtensionName, false, gardenWebhookConfigResources); err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesShoot, constants.GardenerExtensionName, false, runtimeWebhookConfigResources); err != nil {
		return err
	}

	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelSeedCtx()
	if err := managedresources.WaitUntilHealthy(timeoutSeedCtx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesGardenRuntime); err != nil {
		return err
	}

	if err := managedresources.WaitUntilHealthy(timeoutSeedCtx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesGardenVirtual); err != nil {
		return err
	}
	// Wait for both ManagedResources.
	// Cleanup secrets manager after both are healthy.
	return clusterCtx.secretsManager.Cleanup(ctx)
}

func (a *actuator) prepareAssets(
	ctx context.Context,
	logger logr.Logger,
	ex *extensionsv1alpha1.Extension,
	clusterCtx *clusterContext,
	secretConfigs []extensionssecretsmanager.SecretConfigWithOptions,
	allowTrustedKeys bool,
) (
	map[string]*corev1.Secret,
	[]byte,
	[]byte,
	string,
	*lakom.LakomConfig,
	error,
) {
	lakomProviderConfig := &lakom.LakomConfig{}
	if ex.Spec.ProviderConfig != nil {
		if _, _, err := a.decoder.Decode(ex.Spec.ProviderConfig.Raw, nil, lakomProviderConfig); err != nil {
			return nil, nil, nil, "", nil, fmt.Errorf("could not decode provider config, err: %w", err)
		}
	}

	if lakomProviderConfig.Scope == nil {
		lakomProviderConfig.Scope = getScope(a.serviceConfig.DefaultAdmissionScope)
	}
	logger.Info("Extension is configured with admission scope", "scope", *lakomProviderConfig.Scope)

	generatedSecrets, err := extensionssecretsmanager.GenerateAllSecrets(
		ctx,
		clusterCtx.secretsManager,
		secretConfigs,
	)
	if err != nil {
		return nil, nil, nil, "", nil, err
	}

	caBundleSecret, found := clusterCtx.secretsManager.Get(secrets.CAName)
	if !found {
		return nil, nil, nil, "", nil, fmt.Errorf("secret %q not found", secrets.CAName)
	}

	image, err := imagevector.ImageVector().FindImage(constants.ImageName)
	if err != nil {
		return nil, nil, nil, "", nil, fmt.Errorf("failed to find image version for %s: %v", constants.ImageName, err)
	}
	if image.Tag == nil {
		image.Tag = ptr.To[string](version.Get().GitVersion)
	}

	gardenerPublicKeys, err := yaml.JSONToYAML(a.serviceConfig.CosignPublicKeys.Raw)
	if err != nil {
		return nil, nil, nil, "", nil, fmt.Errorf("failed to convert lakom config from json to yaml, %w", err)
	}

	var clientPublicKeys []byte
	if lakomProviderConfig.TrustedKeysResourceName != nil {
		if !allowTrustedKeys {
			return nil, nil, nil, "", nil, fmt.Errorf("trustedKeysResourceName is not supported for garden extension class")
		}

		clientPublicKeys, err = getClientKeys(
			ctx,
			a.client,
			clusterCtx.shootResources,
			*lakomProviderConfig.TrustedKeysResourceName,
			clusterCtx.namespace,
		)
		if err != nil {
			return nil, nil, nil, "", nil, fmt.Errorf("failed to get the additional keys: %w", err)
		}
	}

	return generatedSecrets,
		caBundleSecret.Data[secretsutils.DataKeyCertificateBundle],
		append(gardenerPublicKeys, clientPublicKeys...),
		image.String(),
		lakomProviderConfig,
		nil
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.delete(ctx, logger, ex, false)
}

// delete deletes the resources deployed for the extension.
// It can be configured to skip deletion of the secretes managed by the SecretsManager.
func (a *actuator) delete(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension, skipSecretManagerSecrets bool) error {
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

	if skipSecretManagerSecrets {
		return nil
	}

	secretsManager, err := extensionssecretsmanager.SecretsManagerForCluster(ctx, logger.WithName("secretsmanager"), clock.RealClock{}, a.client, cluster, secrets.ManagerIdentity, nil)
	if err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

// ForceDelete the Extension resource.
func (a *actuator) ForceDelete(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Delete(ctx, logger, ex)
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

	// SecretsManager secrets should not be deleted during migration in order to have the required ones
	// persisted in the shootstate resource.
	return a.delete(ctx, logger, ex, true)
}

func getLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":    constants.ApplicationName,
		"app.kubernetes.io/part-of": constants.ExtensionType,
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

func getClientKeys(ctx context.Context, client client.Client, resources []gardencorev1beta1.NamedResourceReference, resourceName, namespace string) ([]byte, error) {
	ref := v1beta1helper.GetResourceByName(resources, resourceName)
	if ref == nil {
		return nil, fmt.Errorf("failed to find referenced resource with name %s", resourceName)
	}
	if ref.ResourceRef.Kind != "Secret" {
		return nil, fmt.Errorf("references resource with name %s is not of kind 'Secret'", resourceName)
	}

	refSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.ResourceRef.Name,
			Namespace: namespace,
		},
	}

	if err := controller.GetObjectByReference(ctx, client, &ref.ResourceRef, namespace, refSecret); err != nil {
		return nil, fmt.Errorf("failed to read referenced secret %s%s for reference %s: %w", v1beta1constants.ReferencedResourcesPrefix, ref.ResourceRef.Name, resourceName, err)
	}

	clientKeys, ok := refSecret.Data["keys"]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s is missing data key 'keys'", refSecret.Namespace, refSecret.Name)
	}

	return clientKeys, nil
}

// clusterContext contains cluster-specific settings extracted based on the extension class (shoot or garden).
type clusterContext struct {
	namespace                   string
	genericTokenKubeconfigName  string
	secretsManager              secretsmanager.Interface
	kubernetesVersion           string
	topologyAwareRoutingEnabled bool
	hibernated                  bool
	dashboardEnabled            bool
	shootResources              []gardencorev1beta1.NamedResourceReference
}

// buildShootClusterContext extracts cluster info for extensions with shoot extension class
func (a *actuator) buildShootClusterContext(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) (*clusterContext, error) {
	namespace := ex.GetNamespace()

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return nil, err
	}

	if cluster.Seed == nil || cluster.Seed.Status.KubernetesVersion == nil || len(*cluster.Seed.Status.KubernetesVersion) == 0 {
		return nil, fmt.Errorf("missing or empty `cluster.seed.status.kubernetesVersion`")
	}

	configs := secrets.ConfigsFor(namespace)
	secretsManager, err := extensionssecretsmanager.SecretsManagerForCluster(
		ctx,
		log.WithName("secretsmanager"),
		clock.RealClock{},
		a.client,
		cluster,
		secrets.ManagerIdentity,
		configs,
	)
	if err != nil {
		return nil, err
	}

	return &clusterContext{
		namespace:                   namespace,
		genericTokenKubeconfigName:  extensions.GenericTokenKubeconfigSecretNameFromCluster(cluster),
		secretsManager:              secretsManager,
		kubernetesVersion:           *cluster.Seed.Status.KubernetesVersion,
		topologyAwareRoutingEnabled: v1beta1helper.IsTopologyAwareRoutingForShootControlPlaneEnabled(cluster.Seed, cluster.Shoot),
		hibernated:                  controller.IsHibernationEnabled(cluster),
		dashboardEnabled:            v1beta1helper.KubernetesDashboardEnabled(cluster.Shoot.Spec.Addons), //nolint:staticcheck
		shootResources:              cluster.Shoot.Spec.Resources,
	}, nil
}

// buildGardenClusterContext extracts cluster info for extensions with garden extension class
func (a *actuator) buildGardenClusterContext(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) (*clusterContext, error) {
	namespace := ex.GetNamespace()

	garden, err := a.getGarden(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get garden: %w", err)
	}

	genericTokenKubeconfigName, ok := garden.Annotations[v1beta1constants.AnnotationKeyGenericTokenKubeconfigSecretName]
	if !ok || genericTokenKubeconfigName == "" {
		return nil, fmt.Errorf("no generic token kubeconfig secret found in garden object annotations")
	}

	configs := secrets.ConfigsFor(namespace)
	secretsManager, err := extensionssecretsmanager.SecretsManagerForGarden(
		ctx,
		log.WithName("secretsmanager"),
		clock.RealClock{},
		a.client,
		garden,
		secrets.ManagerIdentityRuntime,
		configs,
		namespace,
	)
	if err != nil {
		return nil, err
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(a.config)
	if err != nil {
		return nil, fmt.Errorf("could not create discovery client: %w", err)
	}
	versionInfo, err := discoveryClient.ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("could not get runtime cluster server version: %w", err)
	}

	if _, err := semver.NewVersion(versionInfo.GitVersion); err != nil {
		return nil, fmt.Errorf("failed to parse runtime cluster Kubernetes version %q: %w", versionInfo.GitVersion, err)
	}

	return &clusterContext{
		namespace:                   namespace,
		genericTokenKubeconfigName:  genericTokenKubeconfigName,
		secretsManager:              secretsManager,
		kubernetesVersion:           versionInfo.GitVersion,
		topologyAwareRoutingEnabled: operatorv1alpha1helper.TopologyAwareRoutingEnabled(garden.Spec.RuntimeCluster.Settings),
	}, nil
}

func (a *actuator) getGarden(ctx context.Context) (*operatorv1alpha1.Garden, error) {
	gardenList := &operatorv1alpha1.GardenList{}
	if err := a.client.List(ctx, gardenList); err != nil {
		return nil, err
	}

	if len(gardenList.Items) == 0 {
		return nil, fmt.Errorf("no garden object found")
	}

	if len(gardenList.Items) > 1 {
		return nil, fmt.Errorf("found more than one garden object")
	}

	return &gardenList.Items[0], nil
}
