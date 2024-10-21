// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	lakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LakomConfig contains information about the Lakom service configuration.
type LakomConfig struct {
	metav1.TypeMeta

	// The scope in which lakom will verify pods
	// +optional
	Scope *lakom.ScopeType `json:"scope"`
	// CosignPublicKeys is the cosign public keys used to verify image signatures.
	// +optional
	PublicKeysSecretReference *string `json:"publicKeysSecretReference,omitempty"`
}
