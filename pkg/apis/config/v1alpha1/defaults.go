// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

// SetDefaults_Configuration sets defaults for the extension controller configuration.
func SetDefaults_Configuration(obj *Configuration) {
	if obj.UseOnlyImagePullSecrets == nil {
		obj.UseOnlyImagePullSecrets = ptr.To(true)
	}
}
