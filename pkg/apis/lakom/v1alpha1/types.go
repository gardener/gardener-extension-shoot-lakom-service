// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ScopeType string

const (
	KubeSystem                  ScopeType = "kubeSystem"
	KubeSystemManagedByGardener ScopeType = "kubeSystemManagedByGardener"
	Cluster                     ScopeType = "Cluster"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Configuration contains information about the Lakom service configuration.
type LakomConfig struct {
	metav1.TypeMeta

	// The scope in which lakom will verify pods
	// +optional
	Scope ScopeType `json:"scope"`
}
