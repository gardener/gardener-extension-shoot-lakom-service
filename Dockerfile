# SPDX-FileCopyrightText: Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

############# builder
FROM --platform=$BUILDPLATFORM golang:1.27.3 AS builder

ARG EFFECTIVE_VERSION
ARG TARGETOS
ARG TARGETARCH
WORKDIR /go/src/github.com/gardener/gardener-extension-shoot-lakom-service

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build EFFECTIVE_VERSION=$EFFECTIVE_VERSION GOOS=$TARGETOS GOARCH=$TARGETARCH BUILD_OUTPUT_FILE="/output/bin/"

############# base
FROM gcr.io/distroless/static-debian13:nonroot@sha256:516757106de35205efb70b91ba03f6f1298424a0678c603255cf2852a7000087 AS base

############# lakom
FROM base AS lakom
WORKDIR /

COPY --from=builder /output/bin/lakom /lakom
ENTRYPOINT ["/lakom"]

############# gardener-extension-shoot-lakom-service
FROM base AS gardener-extension-shoot-lakom-service

COPY charts /charts
COPY --from=builder /output/bin/gardener-extension-shoot-lakom-service /gardener-extension-shoot-lakom-service
ENTRYPOINT ["/gardener-extension-shoot-lakom-service"]


############# gardener-extension-shoot-lakom-admission
FROM base AS gardener-extension-shoot-lakom-admission

COPY --from=builder /output/bin/gardener-extension-shoot-lakom-admission /gardener-extension-shoot-lakom-admission
ENTRYPOINT ["/gardener-extension-shoot-lakom-admission"]
