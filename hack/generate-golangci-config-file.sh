#!/usr/bin/env bash

# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

GARDENER_GOLANGCI_CONFIG=${GARDENER_HACK_DIR}/../.golangci.yaml.in
LAKOM_GOLANGCI_CONFIG=${REPO_ROOT}/.golangci.yaml.in
GOLANGCI_CONFIG=${REPO_ROOT}/.golangci.yaml

if [ ! -s ${GARDENER_GOLANGCI_CONFIG} ]; then
    exit 1
fi

if [ ! -s ${LAKOM_GOLANGCI_CONFIG} ]; then
    exit 1
fi

importas_alias=$(yq eval-all '.["linters-settings"].importas.alias as $item ireduce ([]; . + $item) | unique' ${GARDENER_GOLANGCI_CONFIG} ${LAKOM_GOLANGCI_CONFIG})
importas_alias=${importas_alias} yq '.["linters-settings"].importas.alias = env(importas_alias)' ${LAKOM_GOLANGCI_CONFIG} > ${GOLANGCI_CONFIG}
