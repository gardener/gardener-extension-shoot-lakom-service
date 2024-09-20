// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lakom

import (
	"context"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// shoot validates shoots
type shoot struct {
	apiReader client.Reader
	decoder   runtime.Decoder
}

// NewShootValidator returns a new instance of a shoot validator.
func NewShootValidator(apiReader client.Reader, decoder runtime.Decoder) extensionswebhook.Validator {
	return &shoot{
		apiReader: apiReader,
		decoder:   decoder,
	}
}

func findExtension(extensions []core.Extension, extensionType string) (int, core.Extension) {
	for i, ext := range extensions {
		if ext.Type == extensionType {
			return i, ext
		}
	}

	return -1, core.Extension{}
}

func (s *shoot) validateScopeType(fldPath *field.Path, scopeType lakom.ScopeType) field.ErrorList {
	errList := field.ErrorList{}

	if !lakom.AllowedScopes.Has(scopeType) {
		errList = append(errList, field.NotSupported(fldPath, scopeType, lakom.AllowedScopes.UnsortedList()))
	}

	return errList
}

// Validate validates the given shoot object
func (s *shoot) Validate(_ context.Context, new, _ client.Object) error {
	shoot, ok := new.(*core.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T, expected core.Shoot", new)
	}

	i, lakomExt := findExtension(shoot.Spec.Extensions, constants.ExtensionType)
	if i == -1 {
		return nil
	}

	lakomConfig := &lakom.LakomConfig{}
	if err := runtime.DecodeInto(s.decoder, lakomExt.ProviderConfig.Raw, lakomConfig); err != nil {
		return fmt.Errorf("failed to decode providerConfig: %w", err)
	}
	if lakomConfig.Scope == nil {
		return nil
	}

	providerConfigPath := field.NewPath("spec", "extensions").Index(i).Child("providerConfig")
	if lakomExt.ProviderConfig == nil {
		return nil
	}

	return s.validateScopeType(providerConfigPath.Child("scope"), *lakomConfig.Scope).ToAggregate()
}
