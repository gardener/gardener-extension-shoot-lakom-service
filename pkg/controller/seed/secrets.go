// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package seed

import (
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
)

const (
	// ManagerIdentity is the identity used for the secrets manager.
	ManagerIdentity = constants.SeedExtensionServiceName
	// CAName is the name of the CA secret.
	CAName = "ca-" + ManagerIdentity
)

// ConfigsFor returns configurations for the secrets manager for the given namespace.
func ConfigsFor(namespace string) []extensionssecretsmanager.SecretConfigWithOptions {
	return []extensionssecretsmanager.SecretConfigWithOptions{
		{
			Config: &secretutils.CertificateSecretConfig{
				Name:       CAName,
				CommonName: CAName,
				CertType:   secretutils.CACert,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.Persist()},
		},
		{
			Config: &secretutils.CertificateSecretConfig{
				Name:                        constants.SeedWebhookTLSSecretName,
				CommonName:                  constants.SeedExtensionServiceName,
				DNSNames:                    kutil.DNSNamesForService(constants.SeedExtensionServiceName, namespace),
				CertType:                    secretutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			// use current CA for signing server cert to prevent mismatches when dropping the old CA from the webhook
			// config in phase Completing
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(CAName, secretsmanager.UseCurrentCA)},
		},
	}
}
