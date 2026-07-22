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

	seedResources, err := getSeedResources(
		clusterCtx,
		getLakomReplicas(clusterCtx.hibernated),
		constants.ExtensionServiceName,
		lakomShootAccessSecret.Secret.Name,
		clusterCtx.generatedSecrets[constants.WebhookTLSSecretName].Name,
		a.serviceConfig.UseOnlyImagePullSecrets,
		a.serviceConfig.AllowUntrustedImages,
		a.serviceConfig.AllowInsecureRegistries,
	)
	if err != nil {
		return err
	}

	shootWebhookOptions := shootWebhookOptions(
		constants.WebhookConfigurationName,
		lakomShootAccessSecret.ServiceAccountName,
		*clusterCtx.providerConfig.Scope,
		clusterCtx.dashboardEnabled,
		clusterCtx.caBundle,
	)
	shootResources, err := getWebhookResources(shootWebhookOptions, shootWebhookRules, constants.ExtensionServiceName, clusterCtx.namespace)
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
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: constants.LakomSystemNamespaceName}}
	if err := client.IgnoreAlreadyExists(a.client.Create(ctx, ns)); err != nil {
		return fmt.Errorf("failed to create namespace %s: %w", constants.LakomSystemNamespaceName, err)
	}

	clusterCtx, err := a.buildGardenClusterContext(ctx, logger, ex)
	if err != nil {
		return err
	}

	gardenAccessSecret := gardenerutils.NewGardenAccessSecret(
		gardenerutils.SecretNamePrefixGardenAccess+constants.ApplicationName,
		clusterCtx.namespace,
	)

	gardenAccessSecret.Secret.SetLabels(utils.MergeStringMaps(getLabels(), gardenAccessSecret.Secret.GetLabels()))
	if err := gardenAccessSecret.Reconcile(ctx, a.client); err != nil {
		return err
	}

	gardenRuntimeResources, err := getGardenRuntimeResources(
		clusterCtx,
		getLakomReplicas(false),
		clusterCtx.generatedSecrets[constants.GardenRuntimeWebhookTLSSecretName].Name,
		a.serviceConfig.UseOnlyImagePullSecrets,
		a.serviceConfig.AllowUntrustedImages,
		a.serviceConfig.AllowInsecureRegistries,
	)
	if err != nil {
		return err
	}

	gardenVirtualResources, err := getGardenVirtualResources(
		clusterCtx,
		getLakomReplicas(false),
		gardenAccessSecret.Secret.Name,
		a.serviceConfig.UseOnlyImagePullSecrets,
		a.serviceConfig.AllowUntrustedImages,
		a.serviceConfig.AllowInsecureRegistries,
	)
	if err != nil {
		return err
	}

	gardenRuntimeWebhookConfigResources, err := getWebhookResources(
		gardenRuntimeWebhookOptions(clusterCtx.caBundle),
		gardenRuntimeWebhookRules,
		constants.GardenRuntimeExtensionServiceName,
		constants.LakomSystemNamespaceName,
	)
	if err != nil {
		return err
	}

	gardenVirtualWebhookConfigResources, err := getWebhookResources(
		gardenVirtualWebhookOptions(gardenAccessSecret.ServiceAccountName, clusterCtx.caBundle),
		gardenVirtualWebhookRules,
		constants.GardenVirtualExtensionServiceName,
		clusterCtx.namespace,
	)
	if err != nil {
		return err
	}

	timeoutGardenRuntimeCtx, cancelGardenRuntimeCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelGardenRuntimeCtx()

	if err := managedresources.CreateForSeed(ctx,
		a.client,
		clusterCtx.namespace,
		constants.ManagedResourceNamesGardenRuntime,
		false,
		gardenRuntimeResources); err != nil {
		return err
	}

	if err := managedresources.WaitUntilHealthy(timeoutGardenRuntimeCtx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesGardenRuntime); err != nil {
		return err
	}

	timeoutGardenVirtualCtx, cancelGardenVirtualCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelGardenVirtualCtx()

	if err := managedresources.CreateForSeed(ctx,
		a.client,
		clusterCtx.namespace,
		constants.ManagedResourceNamesGardenVirtual,
		false,
		gardenVirtualResources); err != nil {
		return err
	}

	if err := managedresources.WaitUntilHealthy(timeoutGardenVirtualCtx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesGardenVirtual); err != nil {
		return err
	}

	timeoutGardenRuntimeWebhookCtx, cancelGardenRuntimeWebhookCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelGardenRuntimeWebhookCtx()

	if err := managedresources.CreateForSeed(ctx, a.client, clusterCtx.namespace,
		constants.ManagedResourceNamesGardenRuntimeWebhook,
		false,
		gardenRuntimeWebhookConfigResources); err != nil {
		return err
	}

	if err := managedresources.WaitUntilHealthy(timeoutGardenRuntimeWebhookCtx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesGardenRuntimeWebhook); err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx,
		a.client,
		clusterCtx.namespace,
		constants.ManagedResourceNamesGardenVirtualWebhook,
		constants.GardenVirtualExtensionServiceName,
		false,
		gardenVirtualWebhookConfigResources); err != nil {
		return err
	}

	// Wait for the ManagedResources.
	// Cleanup secrets manager after they are healthy.
	return clusterCtx.secretsManager.Cleanup(ctx)
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	extensionClass := extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.GetExtensionClass())
	switch extensionClass {
	case extensionsv1alpha1.ExtensionClassShoot:
		return a.deleteShoot(ctx, logger, ex, false)
	case extensionsv1alpha1.ExtensionClassGarden:
		return a.deleteGarden(ctx, logger, ex)
	default:
		return fmt.Errorf("unsupported extension class: %s", extensionClass)
	}
}

// delete deletes the resources deployed for the extension class shoot.
// It can be configured to skip deletion of the secretes managed by the SecretsManager.
func (a *actuator) deleteShoot(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension, skipSecretManagerSecrets bool) error {
	namespace := ex.GetNamespace()

	timeoutShootCtx, cancelShootCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelShootCtx()

	if err := managedresources.DeleteForShoot(ctx, a.client, namespace, constants.ManagedResourceNamesShoot); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutShootCtx, a.client, namespace, constants.ManagedResourceNamesShoot); err != nil {
		return err
	}

	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, 2*time.Minute)
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

	if skipSecretManagerSecrets {
		return nil
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

// delete deletes the resources deployed for the extension class garden.
// It can be configured to skip deletion of the secretes managed by the SecretsManager.
func (a *actuator) deleteGarden(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) error {
	namespace := ex.GetNamespace()

	timeoutGardenRuntimeWebhookCtx, cancelGardenRuntimeWebhookCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelGardenRuntimeWebhookCtx()
	if err := managedresources.DeleteForSeed(ctx, a.client, namespace, constants.ManagedResourceNamesGardenRuntimeWebhook); err != nil {
		return err
	}
	if err := managedresources.WaitUntilDeleted(timeoutGardenRuntimeWebhookCtx, a.client, namespace, constants.ManagedResourceNamesGardenRuntimeWebhook); err != nil {
		return err
	}

	timeoutGardenVirtualWebhookCtx, cancelGardenVirtualWebhookCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelGardenVirtualWebhookCtx()
	if err := managedresources.DeleteForShoot(ctx, a.client, namespace, constants.ManagedResourceNamesGardenVirtualWebhook); err != nil {
		return err
	}
	if err := managedresources.WaitUntilDeleted(timeoutGardenVirtualWebhookCtx, a.client, namespace, constants.ManagedResourceNamesGardenVirtualWebhook); err != nil {
		return err
	}

	timeoutGardenRuntimeCtx, cancelGardenRuntimeCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelGardenRuntimeCtx()
	if err := managedresources.DeleteForSeed(ctx, a.client, namespace, constants.ManagedResourceNamesGardenRuntime); err != nil {
		return err
	}
	if err := managedresources.WaitUntilDeleted(timeoutGardenRuntimeCtx, a.client, namespace, constants.ManagedResourceNamesGardenRuntime); err != nil {
		return err
	}

	timeoutGardenVirtualCtx, cancelGardenVirtualCtx := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelGardenVirtualCtx()
	if err := managedresources.DeleteForSeed(ctx, a.client, namespace, constants.ManagedResourceNamesGardenVirtual); err != nil {
		return err
	}
	if err := managedresources.WaitUntilDeleted(timeoutGardenVirtualCtx, a.client, namespace, constants.ManagedResourceNamesGardenVirtual); err != nil {
		return err
	}

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: constants.LakomSystemNamespaceName}}
	if err := client.IgnoreNotFound(a.client.Delete(ctx, ns)); err != nil {
		return fmt.Errorf("failed to delete namespace %s: %w", constants.LakomSystemNamespaceName, err)
	}

	garden, err := a.getGarden(ctx)
	if err != nil {
		return err
	}

	secretsManager, err := extensionssecretsmanager.SecretsManagerForGarden(ctx,
		logger.WithName("secretsmanager"),
		clock.RealClock{},
		a.client,
		garden,
		secrets.ManagerIdentityGarden,
		nil,
		namespace,
		constants.LakomSystemNamespaceName)
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
	// SecretsManager secrets should not be deleted during migration in order to have the required ones
	// persisted in the shootstate resource.
	extensionClass := extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.GetExtensionClass())
	switch extensionClass {
	case extensionsv1alpha1.ExtensionClassShoot:
		// Keep objects for shoot managed resources so that they are not deleted from the shoot during the migration
		if err := managedresources.SetKeepObjects(ctx, a.client, ex.GetNamespace(), constants.ManagedResourceNamesShoot, true); err != nil {
			return err
		}
		return a.deleteShoot(ctx, logger, ex, true)
	default:
		return fmt.Errorf("unsupported extension class: %s", extensionClass)
	}
}

func getLabels() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":    constants.ApplicationName,
		"app.kubernetes.io/part-of": constants.ExtensionType,
	}
}

// getGardenPodLabels returns the pod selector/template labels for a garden deployment variant.
func getGardenPodLabels(virtualGarden bool) map[string]string {
	instance := constants.GardenRuntimeExtensionServiceName
	if virtualGarden {
		instance = constants.GardenVirtualExtensionServiceName
	}

	return utils.MergeStringMaps(getLabels(), map[string]string{
		"app.kubernetes.io/instance": instance,
	})
}

// getClientKeys retrieves the client keys from a referenced secret resource.
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

// clusterContext contains cluster-specific settings extracted based on the extension class
type clusterContext struct {
	namespace                   string
	genericTokenKubeconfigName  string
	secretsManager              secretsmanager.Interface
	kubernetesVersion           string
	topologyAwareRoutingEnabled bool
	hibernated                  bool
	dashboardEnabled            bool

	caName                string
	caBundle              []byte
	generatedSecrets      map[string]*corev1.Secret
	lakomPublicKeysConfig []byte
	image                 string
	providerConfig        *lakom.LakomConfig
}

// buildShootClusterContext extracts cluster info and assets for extensions with extension class shoot.
func (a *actuator) buildShootClusterContext(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) (*clusterContext, error) {
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
		logger.WithName("secretsmanager"),
		clock.RealClock{},
		a.client,
		cluster,
		secrets.ManagerIdentity,
		configs,
	)
	if err != nil {
		return nil, err
	}

	clusterCtx := &clusterContext{
		namespace:                   namespace,
		genericTokenKubeconfigName:  extensions.GenericTokenKubeconfigSecretNameFromCluster(cluster),
		secretsManager:              secretsManager,
		kubernetesVersion:           *cluster.Seed.Status.KubernetesVersion,
		topologyAwareRoutingEnabled: v1beta1helper.IsTopologyAwareRoutingForShootControlPlaneEnabled(cluster.Seed, cluster.Shoot),
		hibernated:                  controller.IsHibernationEnabled(cluster),
		dashboardEnabled:            v1beta1helper.KubernetesDashboardEnabled(cluster.Shoot.Spec.Addons), //nolint:staticcheck
		caName:                      secrets.CAName,
	}

	if err := a.prepareTLSSecrets(ctx, clusterCtx, configs); err != nil {
		return nil, err
	}
	if err := a.prepareAdmissionConfig(ctx, ex, clusterCtx, cluster.Shoot.Spec.Resources); err != nil {
		return nil, err
	}

	return clusterCtx, nil
}

// buildGardenClusterContext extracts cluster info and assets for extensions with extension class garden.
func (a *actuator) buildGardenClusterContext(ctx context.Context, logger logr.Logger, ex *extensionsv1alpha1.Extension) (*clusterContext, error) {
	namespace := ex.GetNamespace()
	garden, err := a.getGarden(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get garden: %w", err)
	}

	genericTokenKubeconfigName, ok := garden.Annotations[v1beta1constants.AnnotationKeyGenericTokenKubeconfigSecretName]
	if !ok || genericTokenKubeconfigName == "" {
		return nil, fmt.Errorf("no generic token kubeconfig secret found in garden object annotations")
	}

	configs := secrets.ConfigsForGarden()
	secretsManager, err := extensionssecretsmanager.SecretsManagerForGarden(
		ctx,
		logger.WithName("secretsmanager"),
		clock.RealClock{},
		a.client,
		garden,
		secrets.ManagerIdentityGarden,
		configs,
		namespace,
		constants.LakomSystemNamespaceName,
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

	clusterCtx := &clusterContext{
		namespace:                   namespace,
		genericTokenKubeconfigName:  genericTokenKubeconfigName,
		secretsManager:              secretsManager,
		kubernetesVersion:           versionInfo.GitVersion,
		topologyAwareRoutingEnabled: operatorv1alpha1helper.TopologyAwareRoutingEnabled(garden.Spec.RuntimeCluster.Settings),
		caName:                      secrets.CANameGarden,
	}

	if err := a.prepareTLSSecrets(ctx, clusterCtx, configs); err != nil {
		return nil, err
	}
	if err := a.prepareAdmissionConfig(ctx, ex, clusterCtx, garden.Spec.Resources); err != nil {
		return nil, err
	}

	return clusterCtx, nil
}

// prepareTLSSecrets generates all TLS secrets via the secrets manager, fetches the CA bundle
// and populates relevant fields in the cluster context
func (a *actuator) prepareTLSSecrets(ctx context.Context, clusterCtx *clusterContext, secretsConfigs []extensionssecretsmanager.SecretConfigWithOptions) error {
	generatedSecrets, err := extensionssecretsmanager.GenerateAllSecrets(ctx, clusterCtx.secretsManager, secretsConfigs)
	if err != nil {
		return err
	}
	clusterCtx.generatedSecrets = generatedSecrets

	caBundleSecret, found := clusterCtx.secretsManager.Get(clusterCtx.caName, secretsmanager.Bundle)
	if !found {
		return fmt.Errorf("secret %q not found", clusterCtx.caName)
	}
	clusterCtx.caBundle = caBundleSecret.Data[secretsutils.DataKeyCertificateBundle]

	return nil
}

// prepareAdmissionConfig decodes the provider config, resolves the lakom container image,
// assembles the cosign public keys and populates relevant fields in the cluster context.
func (a *actuator) prepareAdmissionConfig(
	ctx context.Context,
	ex *extensionsv1alpha1.Extension,
	clusterCtx *clusterContext,
	namedResourceRef []gardencorev1beta1.NamedResourceReference,
) error {
	clusterCtx.providerConfig = &lakom.LakomConfig{}
	if ex.Spec.ProviderConfig != nil {
		if _, _, err := a.decoder.Decode(ex.Spec.ProviderConfig.Raw, nil, clusterCtx.providerConfig); err != nil {
			return fmt.Errorf("could not decode provider config, err: %w", err)
		}
	}

	if clusterCtx.providerConfig.Scope == nil {
		clusterCtx.providerConfig.Scope = getScope(a.serviceConfig.DefaultAdmissionScope)
	}

	image, err := imagevector.ImageVector().FindImage(constants.ImageName)
	if err != nil {
		return fmt.Errorf("failed to find image version for %s: %v", constants.ImageName, err)
	}
	if image.Tag == nil {
		image.Tag = ptr.To[string](version.Get().GitVersion)
	}
	clusterCtx.image = image.String()

	gardenerPublicKeys, err := yaml.JSONToYAML(a.serviceConfig.CosignPublicKeys.Raw)
	if err != nil {
		return fmt.Errorf("failed to convert cosign public keys from json to yaml, %w", err)
	}

	var clientPublicKeys []byte
	if clusterCtx.providerConfig.TrustedKeysResourceName != nil {
		clientPublicKeys, err = getClientKeys(
			ctx,
			a.client,
			namedResourceRef,
			*clusterCtx.providerConfig.TrustedKeysResourceName,
			clusterCtx.namespace,
		)
		if err != nil {
			return fmt.Errorf("failed to get the additional keys: %w", err)
		}
	}
	lakomPublicKeys := make([]byte, 0, len(gardenerPublicKeys)+len(clientPublicKeys))
	lakomPublicKeys = append(lakomPublicKeys, gardenerPublicKeys...)
	lakomPublicKeys = append(lakomPublicKeys, clientPublicKeys...)
	clusterCtx.lakomPublicKeysConfig = lakomPublicKeys

	return nil
}

// getGarden retrieves the Garden object from the cluster. It expects exactly one Garden object to be present.
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
