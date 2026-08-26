#!/bin/bash

# SPDX-FileCopyrightText: Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0


set -o errexit
set -o nounset
set -o pipefail

MODFILE="$(go list -m -f '{{.Dir}}' github.com/gardener/gardener/hack/tools)/go.mod"
GOWORK=off go mod download -modfile "${MODFILE}" k8s.io/code-generator
CODE_GEN_DIR=$(GOWORK=off go list -m -modfile "${MODFILE}" -f '{{.Dir}}' k8s.io/code-generator)
source "${CODE_GEN_DIR}/kube_codegen.sh"

PROJECT_ROOT=$(dirname $0)/..


# Code generation for pkg/apis/config
kube::codegen::gen_helpers \
  --boilerplate "${PROJECT_ROOT}/hack/LICENSE_BOILERPLATE.txt" \
  --extra-peer-dir github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config \
  --extra-peer-dir github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config/v1alpha1 \
  --extra-peer-dir k8s.io/apimachinery/pkg/apis/meta/v1 \
  --extra-peer-dir k8s.io/apimachinery/pkg/conversion \
  --extra-peer-dir k8s.io/apimachinery/pkg/runtime \
  --extra-peer-dir github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1 \
  "${PROJECT_ROOT}/pkg/apis/config"

# Code generation for pkg/apis/lakom
kube::codegen::gen_helpers \
  --boilerplate "${PROJECT_ROOT}/hack/LICENSE_BOILERPLATE.txt" \
  --extra-peer-dir github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config \
  --extra-peer-dir github.com/gardener/gardener-extension-shoot-lakom-service/pkg/apis/config/v1alpha1 \
  --extra-peer-dir k8s.io/apimachinery/pkg/apis/meta/v1 \
  --extra-peer-dir k8s.io/apimachinery/pkg/conversion \
  --extra-peer-dir k8s.io/apimachinery/pkg/runtime \
  --extra-peer-dir github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1 \
  "${PROJECT_ROOT}/pkg/apis/lakom"
