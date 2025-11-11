#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

operation="${1:-check}"

echo "> ${operation^} Skaffold Dependencies"

success=true
repo_root="$(git rev-parse --show-toplevel)"

function run() {
  if ! bash "$GARDENER_HACK_DIR"/check-skaffold-deps-for-binary.sh "$operation" --skaffold-file "$1" --binary "$2" --skaffold-config "$3"; then
    success=false
  fi
}

run "skaffold.yaml" "gardener-extension-shoot-lakom-service"                "extension"
run "skaffold.yaml" "lakom"                                                 "extension"
run "skaffold.yaml" "gardener-extension-shoot-lakom-admission"              "admission"
run "skaffold-operator.yaml" "lakom"                                        "operator"
run "skaffold-operator.yaml" "gardener-extension-shoot-lakom-service"       "operator"
run "skaffold-operator.yaml" "gardener-extension-shoot-lakom-admission"     "operator"

if ! $success ; then
  exit 1
fi
