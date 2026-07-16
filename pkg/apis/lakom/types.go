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
	// KubeSystem scope is used to restrict the scope of lakom admission to all pods in the `kube-system` namespaces.
	// When the Gardener `KubernetesDashboard` addon is enabled, the pods in the `kubernetes-dashboard` namespace are also validated.
	KubeSystem ScopeType = "KubeSystem"
	// KubeSystemManagedByGardener scope is used to restrict the scope of lakom admission to the pods in the `kube-system`
	// namespaces that are labeled with `resources.gardener.cloud/managed-by=gardener`.
	// When the Gardener `KubernetesDashboard` addon is enabled, the pods with the same label
	// in the `kubernetes-dashboard` namespace are also validated.
	KubeSystemManagedByGardener ScopeType = "KubeSystemManagedByGardener"
	// Cluster scope configured lakom admission for all pods in all namespaces.
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
	// TrustedKeysResourceName is the name of the shoot resource providing additional cosign public keys for image signature validation.
	TrustedKeysResourceName *string
}
