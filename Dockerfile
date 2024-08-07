# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# builder
FROM golang:1.22.6 AS builder

ARG EFFECTIVE_VERSION
ARG TARGETARCH
WORKDIR /go/src/github.com/gardener/gardener-extension-shoot-lakom-service

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make install EFFECTIVE_VERSION=$EFFECTIVE_VERSION GOARCH=$TARGETARCH

############# base
FROM gcr.io/distroless/static-debian12:nonroot AS base

############# lakom
FROM base AS lakom
WORKDIR /

COPY --from=builder /go/bin/lakom /lakom
ENTRYPOINT ["/lakom"]

############# gardener-extension-shoot-lakom-service
FROM base AS gardener-extension-shoot-lakom-service

COPY charts /charts
COPY --from=builder /go/bin/gardener-extension-shoot-lakom-service /gardener-extension-shoot-lakom-service
ENTRYPOINT ["/gardener-extension-shoot-lakom-service"]
