// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lakom

import (
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	// Name is a name for a validation webhook.
	Name = "lakom-validator"
)

var logger = log.Log.WithName("lakom-validator-webhook")

// New creates a new webhook that validates Shoot and CloudProfile resources.
func New(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Setting up webhook", "name", Name)

	decoder := serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder()
	apiReader := mgr.GetAPIReader()

	return extensionswebhook.New(mgr, extensionswebhook.Args{
		Provider: constants.ExtensionType,
		Name:     Name,
		Path:     "/webhooks/shoot-lakom-admission",
		Validators: map[extensionswebhook.Validator][]extensionswebhook.Type{
			NewShootValidator(apiReader, decoder): {{Obj: &core.Shoot{}}},
		},
		Target: extensionswebhook.TargetSeed,
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"extensions.extensions.gardener.cloud/shoot-lakom-service": "true"},
		},
	})
}
