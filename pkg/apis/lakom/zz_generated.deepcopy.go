//go:build !ignore_autogenerated
// +build !ignore_autogenerated

// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Code generated by deepcopy-gen. DO NOT EDIT.

package lakom

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Key) DeepCopyInto(out *Key) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Key.
func (in *Key) DeepCopy() *Key {
	if in == nil {
		return nil
	}
	out := new(Key)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LakomConfig) DeepCopyInto(out *LakomConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.Scope != nil {
		in, out := &in.Scope, &out.Scope
		*out = new(ScopeType)
		**out = **in
	}
	if in.CosignPublicKeys != nil {
		in, out := &in.CosignPublicKeys, &out.CosignPublicKeys
		*out = make([]Key, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LakomConfig.
func (in *LakomConfig) DeepCopy() *LakomConfig {
	if in == nil {
		return nil
	}
	out := new(LakomConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *LakomConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
