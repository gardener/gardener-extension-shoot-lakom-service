// Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ Object = (*ControlPlane)(nil)

// ControlPlaneResource is a constant for the name of the ControlPlane resource.
const ControlPlaneResource = "ControlPlane"

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,path=controlplanes,shortName=cp,singular=controlplane
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=Type,JSONPath=".spec.type",type=string,description="The control plane type."
// +kubebuilder:printcolumn:name=Purpose,JSONPath=".spec.purpose",type=string,description="Purpose of control plane resource."
// +kubebuilder:printcolumn:name=Status,JSONPath=".status.lastOperation.state",type=string,description="Status of control plane resource."
// +kubebuilder:printcolumn:name=Age,JSONPath=".metadata.creationTimestamp",type=date,description="creation timestamp"

// ControlPlane is a specification for a ControlPlane resource.
type ControlPlane struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the ControlPlane.
	// If the object's deletion timestamp is set, this field is immutable.
	Spec ControlPlaneSpec `json:"spec"`
	// +optional
	Status ControlPlaneStatus `json:"status"`
}

// GetExtensionSpec implements Object.
func (i *ControlPlane) GetExtensionSpec() Spec {
	return &i.Spec
}

// GetExtensionStatus implements Object.
func (i *ControlPlane) GetExtensionStatus() Status {
	return &i.Status
}

// GetExtensionPurpose implements Object.
func (i *ControlPlaneSpec) GetExtensionPurpose() *string {
	return (*string)(i.Purpose)
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ControlPlaneList is a list of ControlPlane resources.
type ControlPlaneList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is the list of ControlPlanes.
	Items []ControlPlane `json:"items"`
}

// ControlPlaneSpec is the spec of a ControlPlane resource.
type ControlPlaneSpec struct {
	// DefaultSpec is a structure containing common fields used by all extension resources.
	DefaultSpec `json:",inline"`
	// Purpose contains the data if a cloud provider needs additional components in order to expose the control plane.
	// This field is immutable.
	// +optional
	Purpose *Purpose `json:"purpose,omitempty"`
	// InfrastructureProviderStatus contains the provider status that has
	// been generated by the controller responsible for the `Infrastructure` resource.
	// +kubebuilder:validation:XPreserveUnknownFields
	// +kubebuilder:pruning:PreserveUnknownFields
	// +optional
	InfrastructureProviderStatus *runtime.RawExtension `json:"infrastructureProviderStatus,omitempty"`
	// Region is the region of this control plane. This field is immutable.
	Region string `json:"region"`
	// SecretRef is a reference to a secret that contains the cloud provider specific credentials.
	SecretRef corev1.SecretReference `json:"secretRef"`
}

// ControlPlaneStatus is the status of a ControlPlane resource.
type ControlPlaneStatus struct {
	// DefaultStatus is a structure containing common fields used by all extension resources.
	DefaultStatus `json:",inline"`
}

// Purpose is a string alias.
type Purpose string

const (
	// Normal triggers the ControlPlane controllers for the shoot provider.
	Normal Purpose = "normal"
	// Exposure triggers the ControlPlane controllers for the exposure settings.
	Exposure Purpose = "exposure"
)
