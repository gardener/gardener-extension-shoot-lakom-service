#!/bin/bash

# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

rootDir="$(readlink -f $(dirname ${0})/..)"
certConfigDir=${rootDir}/config/lakom/tls
cosignConfigDir=${rootDir}/config/lakom/cosign

certDir=${rootDir}/example/lakom/tls
cosignDir=${rootDir}/example/lakom/cosign

ipRoute=$(ip route get 1)
ipAddress=$(echo ${ipRoute#*src} | awk '{print $1}')
