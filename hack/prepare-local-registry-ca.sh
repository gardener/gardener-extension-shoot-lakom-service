#!/usr/bin/env bash
# SPDX-FileCopyrightText: Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

kubectl=${KUBECTL:-kubectl}
yq=${YQ:-yq}
patch_dir="$(dirname "$0")/../local-setup/operator"

# Use the same kubeconfig/context as Skaffold's deployment to the runtime cluster.
if ! registry_ca_secret=$("$kubectl" --request-timeout=30s -n garden get secret gardener-local-registry-ca -o json); then
  echo "Failed to read garden/gardener-local-registry-ca. Point KUBECONFIG at the local garden runtime cluster and complete Gardener's local setup." >&2
  exit 1
fi

registry_ca=$(printf '%s' "$registry_ca_secret" | "$yq" -r '.data."bundle.crt" // "" | @base64d')
if [[ -z "$registry_ca" ]]; then
  echo "Secret garden/gardener-local-registry-ca must contain a non-empty bundle.crt." >&2
  exit 1
fi

patch_file=$(mktemp "$patch_dir/patch-registry-ca.XXXXXX")
trap 'rm -f "$patch_file"' EXIT

REGISTRY_CA="$registry_ca" "$yq" --null-input '
  .apiVersion = "operator.gardener.cloud/v1alpha1" |
  .kind = "Extension" |
  .metadata.name = "extension-shoot-lakom-service" |
  .spec.deployment.extension.values.imageVectorOverwrite.caBundle.inline = strenv(REGISTRY_CA) |
  .spec.deployment.extension.runtimeClusterValues.imageVectorOverwrite.caBundle.inline = strenv(REGISTRY_CA)
' > "$patch_file"
mv "$patch_file" "$patch_dir/patch-registry-ca.yaml"
