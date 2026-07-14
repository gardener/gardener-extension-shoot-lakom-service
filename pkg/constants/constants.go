// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	// ApplicationName is the name for resource describing the components deployed by the extension controller.
	ApplicationName = "lakom"
	// ImageName is the name of the lakom admission controller image.
	ImageName = ApplicationName
	// ExtensionType is the name of the extension type.
	ExtensionType = "shoot-lakom-service"
	// ExtensionServiceName is the extension service name.
	ExtensionServiceName = "extension-" + ExtensionType
	// GardenerExtensionName is the extension name.
	GardenerExtensionName = "gardener-extension-" + ExtensionType
	// GardenRuntimeExtensionServiceName is the name of the Lakom service for the runtime garden deployment.
	GardenRuntimeExtensionServiceName = ExtensionServiceName + "-garden-runtime"
	// GardenVirtualExtensionServiceName is the name of the Lakom service for the virtual garden deployment.
	GardenVirtualExtensionServiceName = ExtensionServiceName + "-garden-virtual"
	// ManagedResourceNamesSeed is the name used to describe the managed seed resources.
	ManagedResourceNamesSeed = ExtensionServiceName + "-seed"
	// ManagedResourceNamesShoot is the name used to describe the managed shoot resources.
	ManagedResourceNamesShoot = ExtensionServiceName + "-shoot"
	// ManagedResourceNamesGardenRuntime is the name used to describe the managed resources deployed on the runtime cluster for the garden extension class.
	ManagedResourceNamesGardenRuntime = ExtensionServiceName + "-garden-runtime"
	// ManagedResourceNamesGardenVirtual is the name used to describe the managed resources deployed on the virtual garden cluster for the garden extension class.
	ManagedResourceNamesGardenVirtual = ExtensionServiceName + "-garden-virtual"
	// ManagedResourceNamesGardenRuntimeWebhook is the name of the seed ManagedResource carrying the runtime garden webhook configs (registered in the runtime cluster).
	ManagedResourceNamesGardenRuntimeWebhook = ExtensionServiceName + "-garden-runtime-webhook"
	// ManagedResourceNamesGardenVirtualShoot is the name of the shoot ManagedResource carrying the virtual garden webhook configs (registered in the virtual garden).
	ManagedResourceNamesGardenVirtualShoot = ExtensionServiceName + "-garden-virtual-shoot"
	// GardenVirtualWebhookTLSSecretName is the name of the TLS secret resource used by the virtual garden lakom webhook.
	GardenVirtualWebhookTLSSecretName = GardenVirtualExtensionServiceName + "-tls"
	// GardenRuntimeWebhookTLSSecretName is the name of the TLS secret resource used by the runtime garden lakom webhook.
	GardenRuntimeWebhookTLSSecretName = GardenRuntimeExtensionServiceName + "-tls"
	// WebhookConfigurationName is the name of the webhook configuration(s) deployed in the shoot cluster.
	WebhookConfigurationName = GardenerExtensionName + "-shoot"
	// GardenVirtualWebhookConfigurationName is the name of the webhook configuration(s) registered in the virtual garden cluster.
	GardenVirtualWebhookConfigurationName = GardenerExtensionName + "-virtual-garden"
	// GardenRuntimeWebhookConfigurationName is the name of the webhook configuration(s) registered in the runtime garden cluster.
	GardenRuntimeWebhookConfigurationName = GardenerExtensionName + "-runtime-garden"
	// WebhookTLSSecretName is the name of the TLS secret resource used by the shoot lakom webhook.
	WebhookTLSSecretName = ExtensionServiceName + "-tls"
	// SeedApplicationName is the name for resource describing the components bootstrapping the seed by the extension controller.
	SeedApplicationName = ApplicationName + "-seed"
	// SeedExtensionServiceName is the extension service name bootstrapping the seed.
	SeedExtensionServiceName = ExtensionServiceName + "-seed"
	// SeedWebhookTLSSecretName is the name of the TLS secret resource used by the lakom webhook in the seed cluster.
	SeedWebhookTLSSecretName = SeedExtensionServiceName + "-tls"
	// LakomResourceReader is the name of the RBAC resources created in the shoot cluster that allow reading image pull secrets
	LakomResourceReader = GardenerExtensionName + "-resource-reader"
	// LakomResolveTagPath is the URL path to the hook resolving image tag to digest.
	LakomResolveTagPath = "/" + ApplicationName + "/resolve-tag-to-digest"
	// LakomVerifyCosignSignaturePath is the URL path to the hook verifying the cosign signature of the image.
	LakomVerifyCosignSignaturePath = "/" + ApplicationName + "/verify-cosign-signature"
	// LakomSystemNamespace is the namespace in which the lakom extension controller is deployed.
	LakomSystemNamespace = ApplicationName + "-system"
)
