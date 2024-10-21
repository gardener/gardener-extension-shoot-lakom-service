// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lakom

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ScopeType determines the namespaces and labels that will be monitored by lakom webhooks
type ScopeType string

const (
	// KubeSystem denotes the `kube-system` namespace
	KubeSystem ScopeType = "KubeSystem"
	// KubeSystemManagedByGardener denotes pods in the `kube-system` namespace that have a `managed-by/gardener` label
	KubeSystemManagedByGardener ScopeType = "KubeSystemManagedByGardener"
	// Cluster denotes the whole cluster
	Cluster ScopeType = "Cluster"
)

// AllowedScopes lists the scopes that can be chosen for lakom.
var AllowedScopes sets.Set[ScopeType] = sets.New(KubeSystem, KubeSystemManagedByGardener, Cluster)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// LakomConfig contains information about the Lakom service configuration.
type LakomConfig struct {
	metav1.TypeMeta

	// The scope in which lakom will verify pods
	Scope *ScopeType
	// CosignPublicKeys is the cosign public keys used to verify image signatures.
	PublicKeysSecretReference *string
}
