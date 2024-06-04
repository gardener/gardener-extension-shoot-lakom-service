#!/bin/bash

# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

set -e

source "$(dirname $0)/common.sh"

caBundle=$(cat ${certDir}/ca.pem | base64 -w0)

cat <<EOF | kubectl apply -f -
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  labels:
    app: lakom
    role: resolve-tag-to-digest
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: lakom
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ${caBundle}
    url: https://${ipAddress}:9443//lakom/resolve-tag-to-digest
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: lakom.gardener.cloud
  namespaceSelector:
    matchExpressions:
    - key: "kubernetes.io/metadata.name"
      operator: "NotIn"
      values: ["kube-system"]
  objectSelector: {}
  reinvocationPolicy: IfNeeded
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - pods
    - pods/ephemeralcontainers
    scope: '*'
  sideEffects: None
  timeoutSeconds: 25
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  labels:
    app: lakom
    role: verify-cosign-signature
    remediation.webhook.shoot.gardener.cloud/exclude: "true"
  name: lakom
webhooks:
- admissionReviewVersions:
  - v1
  clientConfig:
    caBundle: ${caBundle}
    url: https://${ipAddress}:9443//lakom/verify-cosign-signature
  failurePolicy: Fail
  matchPolicy: Equivalent
  name: lakom.gardener.cloud
  namespaceSelector:
    matchExpressions:
    - key: "kubernetes.io/metadata.name"
      operator: "NotIn"
      values: ["kube-system"]
  objectSelector: {}
  rules:
  - apiGroups:
    - ""
    apiVersions:
    - v1
    operations:
    - CREATE
    - UPDATE
    resources:
    - pods
    - pods/ephemeralcontainers
    scope: '*'
  sideEffects: None
  timeoutSeconds: 25
EOF
