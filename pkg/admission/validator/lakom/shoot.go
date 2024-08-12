// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lakom

import (
	"context"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
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

    if ! lakom.AllowedScopes.Has(scopeType) {
            errList = append(errList, field.Invalid(fldPath, scopeType, fmt.Sprintf("Invalid scope %s. Please refer to the documentation for available scopes", scopeType)))
    }

    return errList
}

// Validate validates the given shoot object
func (s *shoot) Validate(_ context.Context, new, _ client.Object) error {
	allErrs := field.ErrorList{}

	shoot, ok := new.(*core.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", new)
	}

	i, lakomExt := findExtension(shoot.Spec.Extensions, constants.ExtensionType)
	if i == -1 {
		return nil
	}

	providerConfigPath := field.NewPath("spec", "extensions").Index(i).Child("providerConfig")
	if lakomExt.ProviderConfig == nil {
		return field.Required(providerConfigPath, "providerConfig is required for the lakom extension")
	}

	lakomConfig := &lakom.LakomConfig{}
	if err := runtime.DecodeInto(s.decoder, lakomExt.ProviderConfig.Raw, lakomConfig); err != nil {
		return fmt.Errorf("failed to decode providerConfig: %w", err)
	}

        allErrs = append(allErrs, s.validateScopeType(providerConfigPath.Child("scope"), lakomConfig.Scope)...)

	return allErrs.ToAggregate()
}
