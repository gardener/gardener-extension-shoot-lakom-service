// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
)

const (
	// ManagerIdentity is the identity used for the secrets manager.
	ManagerIdentity = "extension-" + constants.ExtensionType
	// ManagerIdentityGarden is the identity used for the secrets manager when extension is deployed for garden class extensions.
	ManagerIdentityGarden = "extension-" + constants.ExtensionType + "-garden"
	// CAName is the name of the CA secret.
	CAName = "ca-extension-" + constants.ExtensionType
	// CANameGarden is the name of the CA secret for garden class extensions.
	CANameGarden = "ca-extension-" + constants.ExtensionType + "-garden"
)

// ConfigsFor returns configurations for the secrets manager for the given namespace.
func ConfigsFor(namespace string) []extensionssecretsmanager.SecretConfigWithOptions {
	return []extensionssecretsmanager.SecretConfigWithOptions{
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:       CAName,
				CommonName: CAName,
				CertType:   secretsutils.CACert,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.Persist()},
		},
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:                        constants.WebhookTLSSecretName,
				CommonName:                  constants.ExtensionServiceName,
				DNSNames:                    kubernetesutils.DNSNamesForService(constants.ExtensionServiceName, namespace),
				CertType:                    secretsutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			// use current CA for signing server cert to prevent mismatches when dropping the old CA from the webhook
			// config in phase Completing
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(CAName, secretsmanager.UseCurrentCA)},
		},
	}
}

// ConfigsForGarden returns specific configurations for the secrets manager when Lakom is deployed as extension class garden.
func ConfigsForGarden() []extensionssecretsmanager.SecretConfigWithOptions {
	return []extensionssecretsmanager.SecretConfigWithOptions{
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:       CANameGarden,
				CommonName: CANameGarden,
				CertType:   secretsutils.CACert,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.Persist()},
		},
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:                        constants.GardenVirtualWebhookTLSSecretName,
				CommonName:                  constants.GardenVirtualExtensionServiceName,
				DNSNames:                    kubernetesutils.DNSNamesForService(constants.GardenVirtualExtensionServiceName, v1beta1constants.GardenNamespace),
				CertType:                    secretsutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			Options: []secretsmanager.GenerateOption{
				secretsmanager.SignedByCA(CANameGarden, secretsmanager.UseCurrentCA),
			},
		},
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:                        constants.GardenRuntimeWebhookTLSSecretName,
				CommonName:                  constants.GardenRuntimeExtensionServiceName,
				DNSNames:                    kubernetesutils.DNSNamesForService(constants.GardenRuntimeExtensionServiceName, constants.LakomSystemNamespaceName),
				CertType:                    secretsutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			Options: []secretsmanager.GenerateOption{
				secretsmanager.SignedByCA(CANameGarden, secretsmanager.UseCurrentCA),
				secretsmanager.Namespace(constants.LakomSystemNamespaceName),
			},
		},
	}
}
