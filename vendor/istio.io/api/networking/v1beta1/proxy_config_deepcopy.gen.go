// Code generated by protoc-gen-deepcopy. DO NOT EDIT.
package v1beta1

import (
	proto "google.golang.org/protobuf/proto"
)

// DeepCopyInto supports using ProxyConfig within kubernetes types, where deepcopy-gen is used.
func (in *ProxyConfig) DeepCopyInto(out *ProxyConfig) {
	p := proto.Clone(in).(*ProxyConfig)
	*out = *p
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProxyConfig. Required by controller-gen.
func (in *ProxyConfig) DeepCopy() *ProxyConfig {
	if in == nil {
		return nil
	}
	out := new(ProxyConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInterface is an autogenerated deepcopy function, copying the receiver, creating a new ProxyConfig. Required by controller-gen.
func (in *ProxyConfig) DeepCopyInterface() interface{} {
	return in.DeepCopy()
}

// DeepCopyInto supports using ProxyImage within kubernetes types, where deepcopy-gen is used.
func (in *ProxyImage) DeepCopyInto(out *ProxyImage) {
	p := proto.Clone(in).(*ProxyImage)
	*out = *p
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ProxyImage. Required by controller-gen.
func (in *ProxyImage) DeepCopy() *ProxyImage {
	if in == nil {
		return nil
	}
	out := new(ProxyImage)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInterface is an autogenerated deepcopy function, copying the receiver, creating a new ProxyImage. Required by controller-gen.
func (in *ProxyImage) DeepCopyInterface() interface{} {
	return in.DeepCopy()
}
