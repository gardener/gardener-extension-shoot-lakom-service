// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	healthcheckconfig "github.com/gardener/gardener/extensions/pkg/apis/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Configuration contains information about the Lakom service configuration.
type Configuration struct {
	metav1.TypeMeta

	// HealthCheckConfig is the config for the health check controller.
	HealthCheckConfig *healthcheckconfig.HealthCheckConfig
	// CosignPublicKeys is the cosign public keys used to verify image signatures.
	CosignPublicKeys *runtime.RawExtension
	// DebugConfig contains debug configurations for the controller.
	DebugConfig *DebugConfig
	// SeedBootstrap configures the seed bootstrap controller.
	SeedBootstrap SeedBootstrap
	// UseOnlyImagePullSecrets sets lakom to use only the image pull secrets of the pod to access the OCI registry.
	// Otherwise, also the node identity and docker config file are used.
	UseOnlyImagePullSecrets bool
	// AllowUntrustedImages sets lakom webhook to allow images without trusted signature.
	// Instead to deny the request, the webhook will allow it with a warning.
	AllowUntrustedImages bool
	// AllowInsecureRegistries sets the lakom webhook to allow HTTP communication with OCI registries.
	// It first tries HTTPS and then falls back to HTTP.
	AllowInsecureRegistries bool
}

// DebugConfig contains debug configurations for the controller.
type DebugConfig struct {
	// EnableProfiling enables profiling via web interface host:port/debug/pprof/.
	EnableProfiling bool
	// EnableContentionProfiling enables lock contention profiling, if
	// enableProfiling is true.
	EnableContentionProfiling bool
}

// SeedBootstrap holds configurations for the seed bootstrap controller.
type SeedBootstrap struct {
	// OwnerNamespace is the name of the namespace owning the resources related
	// to the seed bootstrap, as well as where the managed resources are deployed.
	OwnerNamespace string
	// Enabled determines whether any seed bootstrapping will occur.
        // Existing lakom resources will be removed from the seed.
	Enabled bool
}
