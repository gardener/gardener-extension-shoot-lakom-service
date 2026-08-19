// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"encoding/json"
	"slices"

	apislakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	lakomv1alpha1 "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom/v1alpha1"
	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/constants"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"

	"github.com/onsi/gomega"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// AddOrUpdateShootResourceReference adds or updates a resource reference to the given shoot.
func AddOrUpdateShootResourceReference(shoot *gardencorev1beta1.Shoot, resourceRefName, kind, resourceName string) {
	resource := gardencorev1beta1.NamedResourceReference{
		Name: resourceRefName,
		ResourceRef: autoscalingv1.CrossVersionObjectReference{
			Kind:       kind,
			APIVersion: "v1",
			Name:       resourceName,
		},
	}

	i := slices.IndexFunc(shoot.Spec.Resources, func(resource gardencorev1beta1.NamedResourceReference) bool {
		return resource.Name == resourceRefName
	})

	if i == -1 {
		shoot.Spec.Resources = append(shoot.Spec.Resources, resource)
	} else {
		shoot.Spec.Resources[i] = resource
	}
}

// AddOrUpdateGardenResourceReference adds or updates a resource reference to the given garden resource.
func AddOrUpdateGardenResourceReference(garden *operatorv1alpha1.Garden, refName, kind, resourceName string) {
	ref := gardencorev1beta1.NamedResourceReference{
		Name: refName,
		ResourceRef: autoscalingv1.CrossVersionObjectReference{
			Kind:       kind,
			APIVersion: "v1",
			Name:       resourceName,
		},
	}

	i := slices.IndexFunc(garden.Spec.Resources, func(resource gardencorev1beta1.NamedResourceReference) bool {
		return resource.Name == refName
	})
	if i == -1 {
		garden.Spec.Resources = append(garden.Spec.Resources, ref)
	} else {
		garden.Spec.Resources[i] = ref
	}
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
func AddOrUpdateShootLakomExtension(shoot *gardencorev1beta1.Shoot, providerConfig *lakomv1alpha1.LakomConfig) {
	providerConfig.TypeMeta = metav1.TypeMeta{
		APIVersion: lakomv1alpha1.SchemeGroupVersion.String(),
		Kind:       "LakomConfig",
	}

	providerConfigJSON, err := json.Marshal(providerConfig)
	gomega.ExpectWithOffset(1, err).ToNot(gomega.HaveOccurred())

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
}

// AddOrUpdateShootLakomExtensionWithTrustedKeys adds or updates the shoot-lakom-service extension on the given shoot,
// configured with the given admission scope and a reference to a Secret providing additional trusted cosign public keys.
func AddOrUpdateShootLakomExtensionWithTrustedKeys(shoot *gardencorev1beta1.Shoot, scope apislakom.ScopeType, trustedKeysResourceName string) {
	AddOrUpdateShootLakomExtension(shoot, &lakomv1alpha1.LakomConfig{
		Scope:                   &scope,
		TrustedKeysResourceName: &trustedKeysResourceName,
	})
}

// AddOrUpdateGardenLakomExtension adds or updates the shoot-lakom-service extension on the given garden with the provided
// LakomConfig provider config. The extension is enabled (Disabled=false).
func AddOrUpdateGardenLakomExtension(garden *operatorv1alpha1.Garden, providerConfig *lakomv1alpha1.LakomConfig) {
	providerConfig.TypeMeta = metav1.TypeMeta{
		APIVersion: lakomv1alpha1.SchemeGroupVersion.String(),
		Kind:       "LakomConfig",
	}

	providerConfigJSON, err := json.Marshal(providerConfig)
	gomega.ExpectWithOffset(1, err).ToNot(gomega.HaveOccurred())

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
}

// AddOrUpdateGardenLakomExtensionWithTrustedKeys adds or updates the shoot-lakom-service extension on the given garden,
// configured with a reference to a Secret providing additional trusted cosign public keys. Scope is intentionally
// omitted: the garden webhooks have fixed rules, so scope is irrelevant.
func AddOrUpdateGardenLakomExtensionWithTrustedKeys(garden *operatorv1alpha1.Garden, trustedKeysResourceName string) {
	AddOrUpdateGardenLakomExtension(garden, &lakomv1alpha1.LakomConfig{
		TrustedKeysResourceName: &trustedKeysResourceName,
	})
}

// RemoveGardenLakomExtension removes the shoot-lakom-service extension from the given garden resource.
func RemoveGardenLakomExtension(garden *operatorv1alpha1.Garden) {
	garden.Spec.Extensions = slices.DeleteFunc(garden.Spec.Extensions, func(ext operatorv1alpha1.GardenExtension) bool {
		return ext.Type == constants.ExtensionType
	})
}
