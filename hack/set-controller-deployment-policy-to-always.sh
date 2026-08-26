#!/bin/bash

# SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0


set -o errexit
set -o nounset
set -o pipefail

rootDir="$(readlink -f $(dirname ${0})/..)"

yq '(. | select(.kind=="ControllerRegistration") | .spec.deployment.policy) = "Always"' -i $rootDir/example/controller-registration.yaml
