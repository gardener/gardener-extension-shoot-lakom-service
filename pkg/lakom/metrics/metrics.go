// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	runtimemetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	namespace               = "lakom_admission_controller"
	resolvedTagsSubsystem   = "resolved_tags"
	imageSignatureSubsystem = "image_signature_check"

	// CacheHit is label value for cache hit metrics.
	CacheHit = "hit"
	// CacheMiss is label value for cache miss metrics.
	CacheMiss = "miss"
)

var (
	// Factory is used for registering metrics in the controller-runtime metrics registry.
	Factory = promauto.With(runtimemetrics.Registry)

	// ResolvedTag defines the counter resolved_tags_total.
	ResolvedTag = Factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: resolvedTagsSubsystem,
			Name:      "total",
			Help:      "Total number of successfully resolved OCI image tags to digests.",
		},
		[]string{},
	)

	// ResolvedTagErrors defines the counter resolved_tags_errors_total.
	ResolvedTagErrors = Factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: resolvedTagsSubsystem,
			Name:      "errors_total",
			Help:      "Total number of failures OCI image tags to be resolved to digests.",
		},
		[]string{},
	)

	// ResolvedTagCache defines the counter resolved_tags_cache_total.
	ResolvedTagCache = Factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: resolvedTagsSubsystem,
			Name:      "cache_total",
			Help:      "Total number of cache  when resolving OCI image tags to digests.",
		},
		[]string{"status"},
	)

	// ImageSignature defines the counter image_signature_check_total.
	ImageSignature = Factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: imageSignatureSubsystem,
			Name:      "total",
			Help:      "Total number of successful OCI image signatures checks.",
		},
		[]string{"verified"},
	)

	// ImageSignatureErrors defines the counter image_signature_check_errors_total.
	ImageSignatureErrors = Factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: imageSignatureSubsystem,
			Name:      "errors_total",
			Help:      "Total number of failed OCI image signatures checks.",
		},
		[]string{},
	)

	// ImageSignatureCache defines the counter image_signature_check_cache_total.
	ImageSignatureCache = Factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: imageSignatureSubsystem,
			Name:      "cache_total",
			Help:      "Total number of cache when checking image signatures.",
		},
		[]string{"status"},
	)
)
