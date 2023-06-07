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
	// ManagedResourceNamesSeed is the name used to describe the managed seed resources.
	ManagedResourceNamesSeed = ExtensionServiceName + "-seed"
	// ManagedResourceNamesShoot is the name used to describe the managed shoot resources.
	ManagedResourceNamesShoot = ExtensionServiceName + "-shoot"
	// WebhookConfigurationName is the name of the webhook configuration(s) deployed in the shoot cluster.
	WebhookConfigurationName = GardenerExtensionName + "-shoot"
	// WebhookTLSSecretName is the name of the TLS secret resource used by the Lakom webhook in the seed cluster.
	WebhookTLSSecretName = ExtensionServiceName + "-tls"
	// LakomResourceReader is the name of the RBAC resources created in the shoot cluster that allow reading image pull secrets
	LakomResourceReader = GardenerExtensionName + "-resource-reader"
	// LakomResolveTagPath is the URL path to the hook resolving image tag to digest.
	LakomResolveTagPath = "/" + ApplicationName + "/resolve-tag-to-digest"
	// LakomVerifyCosignSignaturePath is the URL path to the hook verifying the cosign signature of the image.
	LakomVerifyCosignSignaturePath = "/" + ApplicationName + "/verify-cosign-signature"
)
