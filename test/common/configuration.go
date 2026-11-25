// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"encoding/json"
	"fmt"
	"slices"

	apislakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	lakomv1alpha1 "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom/v1alpha1"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

// AddOrUpdateShootResourceReference adds or updates a resource reference to the given shoot.
func AddOrUpdateShootResourceReference(shoot *gardencorev1beta1.Shoot, resourceRefName string, resource client.Object, resourceName string, scheme *runtime.Scheme) error {
	refs, err := addOrUpdateResourceRef(shoot.Spec.Resources, resourceRefName, resource, resourceName, scheme)
	if err != nil {
		return err
	}
	shoot.Spec.Resources = refs
	return nil
}

// AddOrUpdateGardenResourceReference adds or updates a resource reference to the given garden resource.
func AddOrUpdateGardenResourceReference(garden *operatorv1alpha1.Garden, refName string, resource client.Object, resourceName string, scheme *runtime.Scheme) error {
	refs, err := addOrUpdateResourceRef(garden.Spec.Resources, refName, resource, resourceName, scheme)
	if err != nil {
		return err
	}
	garden.Spec.Resources = refs
	return nil
}

// addOrUpdateResourceRef returns resources with a NamedResourceReference for refName added or updated to reference
// resourceName. Kind and APIVersion are resolved from resource via scheme rather than hardcoded, because the
// garden/shoot API allows references to resources from APIs other than core/v1. A freshly-constructed typed object
// has an empty TypeMeta, so the GVK is resolved through the scheme (apiutil.GVKForObject) rather than via
// resource.GetObjectKind().
func addOrUpdateResourceRef(resources []gardencorev1beta1.NamedResourceReference, refName string, resource client.Object, resourceName string, scheme *runtime.Scheme) ([]gardencorev1beta1.NamedResourceReference, error) {
	gvk, err := apiutil.GVKForObject(resource, scheme)
	if err != nil {
		return nil, fmt.Errorf("could not determine GroupVersionKind for resource reference %q: %w", refName, err)
	}

	ref := gardencorev1beta1.NamedResourceReference{
		Name: refName,
		ResourceRef: autoscalingv1.CrossVersionObjectReference{
			Kind:       gvk.Kind,
			APIVersion: gvk.GroupVersion().String(),
			Name:       resourceName,
		},
	}

	i := slices.IndexFunc(resources, func(r gardencorev1beta1.NamedResourceReference) bool {
		return r.Name == refName
	})
	if i == -1 {
		resources = append(resources, ref)
	} else {
		resources[i] = ref
	}
	return resources, nil
}

// RemoveShootResourceReference removes the resource reference from the given shoot.
func RemoveShootResourceReference(shoot *gardencorev1beta1.Shoot, resourceRefName string) {
	shoot.Spec.Resources = slices.DeleteFunc(shoot.Spec.Resources, func(resource gardencorev1beta1.NamedResourceReference) bool {
		return resource.Name == resourceRefName
	})
}

// RemoveGardenResourceReference removes NamedResourceReference from the given garden resource by name.
func RemoveGardenResourceReference(garden *operatorv1alpha1.Garden, resourceRefName string) {
	garden.Spec.Resources = slices.DeleteFunc(garden.Spec.Resources, func(resource gardencorev1beta1.NamedResourceReference) bool {
		return resource.Name == resourceRefName
	})
}

// HasResourceReference returns whether the shoot has a named resource reference with the given name.
func HasResourceReference(shoot *gardencorev1beta1.Shoot, resourceRefName string) bool {
	return slices.ContainsFunc(shoot.Spec.Resources, func(resource gardencorev1beta1.NamedResourceReference) bool {
		return resource.Name == resourceRefName
	})
}

// AddOrUpdateShootLakomExtension adds or updates the shoot-lakom-service extension on the given shoot with the provided
// LakomConfig provider config. The extension is enabled (Disabled=false).
func AddOrUpdateShootLakomExtension(shoot *gardencorev1beta1.Shoot, providerConfig *lakomv1alpha1.LakomConfig) error {
	providerConfig.TypeMeta = metav1.TypeMeta{
		APIVersion: lakomv1alpha1.SchemeGroupVersion.String(),
		Kind:       "LakomConfig",
	}

	providerConfigJSON, err := json.Marshal(providerConfig)
	if err != nil {
		return fmt.Errorf("could not marshal lakom provider config: %w", err)
	}

	extension := gardencorev1beta1.Extension{
		Type: constants.ExtensionType,
		ProviderConfig: &runtime.RawExtension{
			Raw: providerConfigJSON,
		},
	}

	i := slices.IndexFunc(shoot.Spec.Extensions, func(ext gardencorev1beta1.Extension) bool {
		return ext.Type == constants.ExtensionType
	})
	if i == -1 {
		shoot.Spec.Extensions = append(shoot.Spec.Extensions, extension)
	} else {
		shoot.Spec.Extensions[i] = extension
	}
	return nil
}

// AddOrUpdateShootLakomExtensionWithTrustedKeys adds or updates the shoot-lakom-service extension on the given shoot,
// configured with the given admission scope and a reference to a Secret providing additional trusted cosign public keys.
func AddOrUpdateShootLakomExtensionWithTrustedKeys(shoot *gardencorev1beta1.Shoot, scope apislakom.ScopeType, trustedKeysResourceName string) error {
	return AddOrUpdateShootLakomExtension(shoot, &lakomv1alpha1.LakomConfig{
		Scope:                   &scope,
		TrustedKeysResourceName: &trustedKeysResourceName,
	})
}

// AddOrUpdateGardenLakomExtension adds or updates the shoot-lakom-service extension on the given garden with the provided
// LakomConfig provider config. The extension is enabled (Disabled=false).
func AddOrUpdateGardenLakomExtension(garden *operatorv1alpha1.Garden, providerConfig *lakomv1alpha1.LakomConfig) error {
	providerConfig.TypeMeta = metav1.TypeMeta{
		APIVersion: lakomv1alpha1.SchemeGroupVersion.String(),
		Kind:       "LakomConfig",
	}

	providerConfigJSON, err := json.Marshal(providerConfig)
	if err != nil {
		return fmt.Errorf("could not marshal lakom provider config: %w", err)
	}

	extension := operatorv1alpha1.GardenExtension{
		Type: constants.ExtensionType,
		ProviderConfig: &runtime.RawExtension{
			Raw: providerConfigJSON,
		},
	}

	i := slices.IndexFunc(garden.Spec.Extensions, func(ext operatorv1alpha1.GardenExtension) bool {
		return ext.Type == constants.ExtensionType
	})
	if i == -1 {
		garden.Spec.Extensions = append(garden.Spec.Extensions, extension)
	} else {
		garden.Spec.Extensions[i] = extension
	}
	return nil
}

// AddOrUpdateGardenLakomExtensionWithTrustedKeys adds or updates the shoot-lakom-service extension on the given garden,
// configured with a reference to a Secret providing additional trusted cosign public keys. Scope is intentionally
// omitted: the garden webhooks have fixed rules, so scope is irrelevant.
func AddOrUpdateGardenLakomExtensionWithTrustedKeys(garden *operatorv1alpha1.Garden, trustedKeysResourceName string) error {
	return AddOrUpdateGardenLakomExtension(garden, &lakomv1alpha1.LakomConfig{
		TrustedKeysResourceName: &trustedKeysResourceName,
	})
}

// RemoveGardenLakomExtension removes the shoot-lakom-service extension from the given garden resource.
func RemoveGardenLakomExtension(garden *operatorv1alpha1.Garden) {
	garden.Spec.Extensions = slices.DeleteFunc(garden.Spec.Extensions, func(ext operatorv1alpha1.GardenExtension) bool {
		return ext.Type == constants.ExtensionType
	})
}
