// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	healthcheckconfigv1alpha1 "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Configuration contains information about the Lakom service configuration.
type Configuration struct {
	metav1.TypeMeta `json:",inline"`

	// HealthCheckConfig is the config for the health check controller.
	// +optional
	HealthCheckConfig *healthcheckconfigv1alpha1.HealthCheckConfig `json:"healthCheckConfig,omitempty"`
	// CosignPublicKeys is the cosign public keys used to verify image signatures.
	CosignPublicKeys []string `json:"cosignPublicKeys,omitempty"`
	// DebugConfig contains debug configurations for the controller.
	// +optional
	DebugConfig *DebugConfig `json:"debugConfig,omitempty"`
	// SeedBootstrap configures the seed bootstrap controller.
	SeedBootstrap SeedBootstrap `json:"seedBootstrap"`
	// UseOnlyImagePullSecrets sets lakom to use only the image pull secrets of the pod to access the OCI registry.
	// Otherwise, also the node identity and docker config file are used.
	UseOnlyImagePullSecrets bool `json:"useOnlyImagePullSecrets"`
	// AllowUntrustedImages sets lakom webhook to allow images without trusted signature.
	// Instead to deny the request, the webhook will allow it with a warning.
	AllowUntrustedImages bool `json:"allowUntrustedImages"`
	// AllowInsecureRegistries allows Lakom to use HTTP for communication with the registries
	AllowInsecureRegistries bool `json:"allowInsecureRegistries"`
}

// DebugConfig contains debug configurations for the controller.
type DebugConfig struct {
	// EnableProfiling enables profiling via web interface host:port/debug/pprof/.
	EnableProfiling bool `json:"enableProfiling"`
	// EnableContentionProfiling enables lock contention profiling, if
	// enableProfiling is true.
	EnableContentionProfiling bool `json:"enableContentionProfiling"`
}

// SeedBootstrap holds configurations for the seed bootstrap controller.
type SeedBootstrap struct {
	// OwnerNamespace is the name of the namespace owning the resources related
	// to the seed bootstrap, as well as where the managed resources are deployed.
	OwnerNamespace string `json:"ownerNamespace"`
}
