// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lakom

import (
	"context"
	"fmt"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/config"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/lakom/utils"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorehelper "github.com/gardener/gardener/pkg/apis/core/helper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
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

// TODO: This check exists in the validation of the lakom config as well. It can be extracted as a util function
func (s *shoot) validateCosignPublicKeys(fldPath *field.Path, cosignPublicKeys []config.Key) field.ErrorList {
	errList := field.ErrorList{}

	usedNames := map[string]any{}
	for idx, k := range cosignPublicKeys {
		if k.Name == "" {
			errList = append(errList, field.Required(fldPath.Index(idx), "key name should no be empty"))
		}

		if _, ok := usedNames[k.Name]; ok {
			errList = append(errList, field.Duplicate(fldPath.Index(idx), k.Name))
		}
		usedNames[k.Name] = nil

		if keys, err := utils.GetCosignPublicKeys([]byte(k.Key)); err != nil {
			errList = append(errList, field.Invalid(fldPath.Index(idx), k.Key, fmt.Sprintf("key %s could not be parsed: %s", k.Name, err)))
		} else if len(keys) != 1 {
			errList = append(errList, field.Invalid(fldPath.Index(idx), k.Key, fmt.Sprintf("multiple keys with the name %s", k.Name)))
		}
	}

	return errList
}

func (s *shoot) validateTrustedKeys(ctx context.Context, fldPath *field.Path, resourceName string, resources []core.NamedResourceReference, namespace string) field.ErrorList {
	ref := gardencorehelper.GetResourceByName(resources, resourceName)
	if ref == nil {
		return field.ErrorList{field.Invalid(fldPath, resourceName, "there is no resource with this name in shoot.spec.resources")}
	}
	if ref.ResourceRef.Kind != "Secret" {
		return field.ErrorList{field.Invalid(fldPath, resourceName, "resource must be of kind 'Secret'")}
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.ResourceRef.Name,
			Namespace: namespace,
		},
	}

	objectKey := client.ObjectKeyFromObject(secret)

	// Explicitly use the client.Reader to prevent controller-runtime to start Informer for Secrets
	// under the hood. The latter increases the memory usage of the component.
	if err := s.apiReader.Get(ctx, objectKey, secret); err != nil {
		return field.ErrorList{field.Invalid(fldPath, resourceName, fmt.Sprintf("failed to get secret %s, %s", objectKey, err.Error()))}
	}

	var keys []config.Key

	rawKeys, ok := secret.Data["keys"]
	if !ok {
		return field.ErrorList{field.Invalid(fldPath, resourceName, fmt.Sprintf("could not get 'keys' in data from secret %s", objectKey))}
	}

	if err := yaml.UnmarshalStrict(rawKeys, &keys); err != nil {
		return field.ErrorList{field.Invalid(fldPath, resourceName, fmt.Sprintf("failed to serialize keys from secret %s: %s", objectKey, err.Error()))}
	}

	return s.validateCosignPublicKeys(fldPath, keys)
}

// Validate validates the given shoot object
func (s *shoot) Validate(ctx context.Context, new, _ client.Object) error {
	shoot, ok := new.(*core.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T, expected core.Shoot", new)
	}

	i, lakomExt := findExtension(shoot.Spec.Extensions, constants.ExtensionType)
	if i == -1 {
		return nil
	}

	providerConfigPath := field.NewPath("spec", "extensions").Index(i).Child("providerConfig")
	if lakomExt.ProviderConfig == nil {
		return nil
	}

	lakomConfig := &lakom.LakomConfig{}
	if err := runtime.DecodeInto(s.decoder, lakomExt.ProviderConfig.Raw, lakomConfig); err != nil {
		return fmt.Errorf("failed to decode providerConfig: %w", err)
	}

	allErrs := field.ErrorList{}

	if lakomConfig.Scope != nil {
		allErrs = append(allErrs, s.validateScopeType(providerConfigPath.Child("scope"), *lakomConfig.Scope)...)
	}
	if lakomConfig.TrustedKeysResourceName != nil {
		allErrs = append(allErrs, s.validateTrustedKeys(ctx, providerConfigPath.Child("trustedKeysResourceName"), *lakomConfig.TrustedKeysResourceName, shoot.Spec.Resources, shoot.Namespace)...)
	}

	return allErrs.ToAggregate()
}
