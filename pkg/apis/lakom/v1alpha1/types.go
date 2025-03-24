// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	apislakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LakomConfig contains information about the Lakom service configuration.
type LakomConfig struct {
	metav1.TypeMeta

	// The scope in which lakom will verify pods
	// +optional
	Scope *apislakom.ScopeType `json:"scope"`
	// TrustedKeysResourceName is the name of the shoot resource providing additional cosign public keys for image signature validation.
	// +optional
	TrustedKeysResourceName *string `json:"trustedKeysResourceName,omitempty"`
}
