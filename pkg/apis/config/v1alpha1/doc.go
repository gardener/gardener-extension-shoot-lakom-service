// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +k8s:deepcopy-gen=package
// +k8s:conversion-gen=github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config
// +k8s:defaulter-gen=TypeMeta
// +k8s:openapi-gen=true

//go:generate crd-ref-docs --source-path . --config ../../../../hack/api-reference/config.yaml --renderer=markdown --templates-dir=${GARDENER_HACK_DIR}/api-reference/template --log-level=ERROR --output-path=../../../../hack/api-reference/config.md

// Package v1alpha1 contains the Lakom Shoot Service extension configuration.
// +groupName=lakom.extensions.config.gardener.cloud
package v1alpha1
