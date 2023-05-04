#!/bin/bash

# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

source "$(dirname $0)/common.sh"

if ! which cosign > /dev/null; then
    echo "It is required cosign to be installed, check docs here https://github.com/sigstore/cosign#installation"
    exit 1
fi

mkdir -p ${cosignDir}

pushd ${cosignDir} > /dev/null
rm -f cosign.pub cosign.key
COSIGN_PASSWORD=$(cat ${cosignConfigDir}/password) cosign generate-key-pair
popd > /dev/null
