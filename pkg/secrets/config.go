// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
)

const (
	// ManagerIdentity is the identity used for the secrets manager.
	ManagerIdentity = "extension-" + constants.ExtensionType
	// CAName is the name of the CA secret.
	CAName = "ca-extension-" + constants.ExtensionType
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
