#!/bin/bash

# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

source "$(dirname $0)/common.sh"

mkdir -p ${certDir}

cat "${certConfigDir}/server-config.json" | sed -e "s/IP_ADDRESS/$ipAddress/g" > "${certDir}/server-config.json"

cfssl gencert \
    -initca ${certConfigDir}/ca-csr.json | \
    cfssljson -bare ${certDir}/ca -

cfssl gencert -profile=server \
    -ca="${certDir}/ca.pem" \
    -ca-key="${certDir}/ca-key.pem" \
    -config="${certConfigDir}/ca-config.json" \
    "${certDir}/server-config.json" | \
    cfssljson -bare ${certDir}/tls


mv ${certDir}/tls.pem ${certDir}/tls.crt
mv ${certDir}/tls-key.pem ${certDir}/tls.key
