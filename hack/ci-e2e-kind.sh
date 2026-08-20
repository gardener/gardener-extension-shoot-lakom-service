#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -o nounset
set -o pipefail
set -o errexit

REPO_ROOT="$(readlink -f "$(dirname "${0}")/..")"
GARDENER_VERSION=$(go list -m -f '{{.Version}}' github.com/gardener/gardener)

if [[ ! -d "$REPO_ROOT/gardener" ]]; then
  git clone --branch "$GARDENER_VERSION" https://github.com/gardener/gardener.git "$REPO_ROOT/gardener"
else
  (cd "$REPO_ROOT/gardener" && git checkout "$GARDENER_VERSION")
fi

source "$REPO_ROOT/gardener/hack/ci-common.sh"

clamp_mss_to_pmtu

# test setup
make -C "$REPO_ROOT/gardener" kind-up
export GARDENER_REPO_ROOT="$REPO_ROOT/gardener"

# export all container logs and events after test execution
trap '{
  export_artifacts "gardener-local"
  make -C "'"$REPO_ROOT"'/gardener" kind-down
}' EXIT

make -C "$REPO_ROOT/gardener" gardener-up

RUNTIME_KUBECONFIG="$GARDENER_REPO_ROOT/dev-setup/kubeconfigs/runtime/kubeconfig"

KUBECONFIG="$RUNTIME_KUBECONFIG" make extension-operator-up
make test-e2e-local-lifecycle

KUBECONFIG="$RUNTIME_KUBECONFIG" make extension-operator-e2e-up
make test-e2e-local-signature
make test-e2e-local-garden

KUBECONFIG="$RUNTIME_KUBECONFIG" make extension-operator-e2e-down
make -C "$REPO_ROOT/gardener" gardener-down
