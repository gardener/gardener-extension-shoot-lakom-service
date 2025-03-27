// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package seed

import (
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	kubernetesutils "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
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
	day := time.Hour * 24
	year := day * 365
	threeMonths := day * 90
	return []extensionssecretsmanager.SecretConfigWithOptions{
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:       CAName,
				CommonName: CAName,
				CertType:   secretsutils.CACert,
				Validity:   &year,
			},
			Options: []secretsmanager.GenerateOption{
				secretsmanager.Rotate(secretsmanager.KeepOld),
				secretsmanager.IgnoreOldSecretsAfter(day),
			},
		},
		{
			Config: &secretsutils.CertificateSecretConfig{
				Name:                        constants.SeedWebhookTLSSecretName,
				CommonName:                  constants.SeedExtensionServiceName,
				DNSNames:                    kubernetesutils.DNSNamesForService(constants.SeedExtensionServiceName, namespace),
				CertType:                    secretsutils.ServerCert,
				SkipPublishingCACertificate: true,
				Validity:                    &threeMonths,
			},

			Options: []secretsmanager.GenerateOption{
				secretsmanager.SignedByCA(
					CAName,
					secretsmanager.UseOldCA,
				),
				secretsmanager.Rotate(secretsmanager.KeepOld),
			},
		},
	}
}
