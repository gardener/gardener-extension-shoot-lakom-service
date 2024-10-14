//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	lakom "github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/lakom"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*LakomConfig)(nil), (*lakom.LakomConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LakomConfig_To_lakom_LakomConfig(a.(*LakomConfig), b.(*lakom.LakomConfig), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*lakom.LakomConfig)(nil), (*LakomConfig)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_lakom_LakomConfig_To_v1alpha1_LakomConfig(a.(*lakom.LakomConfig), b.(*LakomConfig), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_LakomConfig_To_lakom_LakomConfig(in *LakomConfig, out *lakom.LakomConfig, s conversion.Scope) error {
	out.Scope = (*lakom.ScopeType)(unsafe.Pointer(in.Scope))
	out.PublicKeysSecretReference = (*string)(unsafe.Pointer(in.PublicKeysSecretReference))
	return nil
}

// Convert_v1alpha1_LakomConfig_To_lakom_LakomConfig is an autogenerated conversion function.
func Convert_v1alpha1_LakomConfig_To_lakom_LakomConfig(in *LakomConfig, out *lakom.LakomConfig, s conversion.Scope) error {
	return autoConvert_v1alpha1_LakomConfig_To_lakom_LakomConfig(in, out, s)
}

func autoConvert_lakom_LakomConfig_To_v1alpha1_LakomConfig(in *lakom.LakomConfig, out *LakomConfig, s conversion.Scope) error {
	out.Scope = (*lakom.ScopeType)(unsafe.Pointer(in.Scope))
	out.PublicKeysSecretReference = (*string)(unsafe.Pointer(in.PublicKeysSecretReference))
	return nil
}

// Convert_lakom_LakomConfig_To_v1alpha1_LakomConfig is an autogenerated conversion function.
func Convert_lakom_LakomConfig_To_v1alpha1_LakomConfig(in *lakom.LakomConfig, out *LakomConfig, s conversion.Scope) error {
	return autoConvert_lakom_LakomConfig_To_v1alpha1_LakomConfig(in, out, s)
}
