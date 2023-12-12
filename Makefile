# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

EXTENSION_PREFIX            := gardener-extension
EXTENSION_NAME              := shoot-lakom-service
ADMISSION_NAME              := lakom
REGISTRY                    := europe-docker.pkg.dev/gardener-project/public
IMAGE_PREFIX                := $(REGISTRY)/gardener/extensions
REPO_ROOT                   := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
HACK_DIR                    := $(REPO_ROOT)/hack
VERSION                     := $(shell cat "$(REPO_ROOT)/VERSION")
EFFECTIVE_VERSION           := $(VERSION)-$(shell git rev-parse HEAD)
LEADER_ELECTION             := false
LEADER_ELECTION_NAMESPACE   ?= garden
IGNORE_OPERATION_ANNOTATION := true
CACHE_TTL                   ?= 10m
CACHE_REFRESH_INTERVAL      ?= 30s
KUBECONFIG                  ?= $(HOME)/.kube/config
GOARCH                      ?= $(shell go env GOARCH)

TOOLS_DIR := $(HACK_DIR)/tools
include $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/tools.mk
include $(REPO_ROOT)/hack/tools.mk

ifneq ($(strip $(shell git status --porcelain 2>/dev/null)),)
	EFFECTIVE_VERSION := $(EFFECTIVE_VERSION)-dirty
endif

LD_FLAGS := "-w $(shell $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION $(EXTENSION_PREFIX)-$(EXTENSION_NAME))"

.PHONY: start
start:
	@LEADER_ELECTION_NAMESPACE=$(LEADER_ELECTION_NAMESPACE) GO111MODULE=on go run \
		-mod=vendor \
		-ldflags $(LD_FLAGS) \
		./cmd/$(EXTENSION_PREFIX)-$(EXTENSION_NAME) \
		--ignore-operation-annotation=$(IGNORE_OPERATION_ANNOTATION) \
		--leader-election=$(LEADER_ELECTION) \
		--leader-election-id=extension-shoot-lakom-service-leader-election \
		--config=./example/00-config.yaml

.PHONY: start-lakom
start-lakom:
	GO111MODULE=on go run \
		-mod=vendor \
		-ldflags $(LD_FLAGS) \
		./cmd/$(ADMISSION_NAME) \
		--kubeconfig=$(KUBECONFIG) \
		--tls-cert-dir=example/lakom/tls/ \
		--cosign-public-key-path=example/lakom/cosign/cosign.pub \
		--cache-ttl=$(CACHE_TTL) \
		--cache-refresh-interval=$(CACHE_REFRESH_INTERVAL)

.PHONE: dev-setup
dev-setup: $(COSIGN)
	$(HACK_DIR)/generate-certificates.sh
	$(HACK_DIR)/configure-webhook.sh
	$(HACK_DIR)/generate-cosign-key-pair.sh

#################################################################
# Rules related to binary build, Docker image build and release #
#################################################################

.PHONY: install
install:
	@LD_FLAGS=$(LD_FLAGS) \
		$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/install.sh ./...

.PHONY: docker-login
docker-login:
	@gcloud auth activate-service-account --key-file .kube-secrets/gcr/gcr-readwrite.json

.PHONY: docker-images
docker-images:
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) --build-arg TARGETARCH=$(GOARCH) -t $(IMAGE_PREFIX)/$(EXTENSION_NAME):$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(EXTENSION_NAME):latest -f Dockerfile -m 6g --target $(EXTENSION_PREFIX)-$(EXTENSION_NAME) .
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) --build-arg TARGETARCH=$(GOARCH) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):latest -f Dockerfile -m 6g --target $(ADMISSION_NAME) .

#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################

.PHONY: revendor
revendor:
	@GO111MODULE=on go mod tidy
	@GO111MODULE=on go mod vendor
	@chmod +x $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/*
	@chmod +x $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/.ci/*
#	@$(HACK_DIR)/update-github-templates.sh
	@rm -f $(REPO_ROOT)/vendor/github.com/go-openapi/validate/appveyor.yml \
		$(REPO_ROOT)/vendor/github.com/go-openapi/analysis/appveyor.yml \
		$(REPO_ROOT)/vendor/github.com/go-openapi/spec/appveyor.yml

.PHONY: clean
clean:
	@$(shell find ./example -type f -name "controller-registration.yaml" -exec rm '{}' \;)
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/clean.sh ./cmd/... ./pkg/... ./test/...

.PHONY: check-generate
check-generate:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/check-generate.sh $(REPO_ROOT)

.PHONY: check
check: $(GOIMPORTS) $(GOLANGCI_LINT) $(HELM)
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/check.sh --golangci-lint-config=./.golangci.yaml ./cmd/... ./pkg/... # ./test/... # TODO(vpnachev): uncomment when tests are implemented
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/check-charts.sh ./charts

.PHONY: generate
generate: $(GEN_CRD_API_REFERENCE_DOCS) $(HELM) $(MOCKGEN) $(YQ)
	@GO111MODULE=off hack/update-codegen.sh --parallel
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/generate-sequential.sh ./charts/... ./cmd/... ./pkg/... ./test/...
	@$(HACK_DIR)/set-controller-deployment-policy-to-always.sh

.PHONY: format
format: $(GOIMPORTSREVISER)
	@GOIMPORTS_REVISER_OPTIONS="-imports-order std,project,general,company" \
		$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/format.sh ./cmd ./pkg ./test

.PHONY: test
test: $(REPORT_COLLECTOR)
	@SKIP_FETCH_TOOLS=1 $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/test.sh ./cmd/... ./pkg/...

.PHONY: test-cov
test-cov:
	@SKIP_FETCH_TOOLS=1 $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/test-cover.sh ./cmd/... ./pkg/...

.PHONY: test-clean
test-clean:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/test-cover-clean.sh

.PHONY: verify
verify: check format test

.PHONY: verify-extended
verify-extended: check-generate check format test test-cov test-clean
