# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

ENSURE_GARDENER_MOD         := $(shell go get github.com/gardener/gardener@$$(go list -m -f "{{.Version}}" github.com/gardener/gardener))
GARDENER_HACK_DIR           := $(shell go list -m -f "{{.Dir}}" github.com/gardener/gardener)/hack
EXTENSION_PREFIX            := gardener-extension
EXTENSION_NAME              := shoot-lakom-service
EXTENSION_FULL_NAME         := $(EXTENSION_PREFIX)-$(EXTENSION_NAME)
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
include $(GARDENER_HACK_DIR)/tools.mk
include $(REPO_ROOT)/hack/tools.mk

ifneq ($(strip $(shell git status --porcelain 2>/dev/null)),)
	EFFECTIVE_VERSION := $(EFFECTIVE_VERSION)-dirty
endif

EXTENSION_LD_FLAGS := "-w $(shell bash $(GARDENER_HACK_DIR)/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION $(EXTENSION_NAME))"
ADMISSION_LD_FLAGS := "-w $(shell bash $(GARDENER_HACK_DIR)/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION $(ADMISSION_NAME))"

.PHONY: start
start:
	@LEADER_ELECTION_NAMESPACE=$(LEADER_ELECTION_NAMESPACE) go run \
		-ldflags $(EXTENSION_LD_FLAGS) \
		./cmd/$(EXTENSION_FULL_NAME) \
		--ignore-operation-annotation=$(IGNORE_OPERATION_ANNOTATION) \
		--leader-election=$(LEADER_ELECTION) \
		--leader-election-id=extension-shoot-lakom-service-leader-election \
		--config=./example/00-config.yaml

.PHONY: start-lakom
start-lakom:
	@go run \
		-ldflags $(ADMISSION_LD_FLAGS) \
		./cmd/$(ADMISSION_NAME) \
		--kubeconfig=$(KUBECONFIG) \
		--tls-cert-dir=example/lakom/tls/ \
		--cosign-public-key-path=example/lakom/cosign/cosign.pub \
		--cache-ttl=$(CACHE_TTL) \
		--cache-refresh-interval=$(CACHE_REFRESH_INTERVAL)
		--insecure-allow-untrusted-images=true

.PHONE: dev-setup
dev-setup: $(COSIGN)
	@$(HACK_DIR)/generate-certificates.sh
	@$(HACK_DIR)/configure-webhook.sh
	@$(HACK_DIR)/generate-cosign-key-pair.sh

#################################################################
# Rules related to binary build, Docker image build and release #
#################################################################

.PHONY: install
install:
	@LD_FLAGS=$(EXTENSION_LD_FLAGS) \
		bash $(GARDENER_HACK_DIR)/install.sh ./cmd/$(EXTENSION_FULL_NAME)
	@LD_FLAGS=$(ADMISSION_LD_FLAGS) \
		bash $(GARDENER_HACK_DIR)/install.sh ./cmd/$(ADMISSION_NAME)

.PHONY: docker-images
docker-images:
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) --build-arg TARGETARCH=$(GOARCH) -t $(IMAGE_PREFIX)/$(EXTENSION_NAME):$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(EXTENSION_NAME):latest -f Dockerfile -m 6g --target $(EXTENSION_FULL_NAME) .
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) --build-arg TARGETARCH=$(GOARCH) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):latest -f Dockerfile -m 6g --target $(ADMISSION_NAME) .

#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################

.PHONY: tidy
tidy:
	@go mod tidy
	@mkdir -p $(REPO_ROOT)/.ci/hack
	@cp $(GARDENER_HACK_DIR)/.ci/* $(REPO_ROOT)/.ci/hack/
	@chmod +xw $(REPO_ROOT)/.ci/hack/*
	@cp $(GARDENER_HACK_DIR)/cherry-pick-pull.sh $(HACK_DIR)/cherry-pick-pull.sh && chmod +xw $(HACK_DIR)/cherry-pick-pull.sh
#	@$(HACK_DIR)/update-github-templates.sh

.PHONY: clean
clean:
	@$(shell find ./example -type f -name "controller-registration.yaml" -exec rm '{}' \;)
	@bash $(GARDENER_HACK_DIR)/clean.sh ./cmd/... ./pkg/... ./test/...

.PHONY: check-generate
check-generate:
	@bash $(GARDENER_HACK_DIR)/check-generate.sh $(REPO_ROOT)

.PHONY: check
check: $(GOIMPORTS) $(GOLANGCI_LINT) $(HELM)
	@bash $(GARDENER_HACK_DIR)/check.sh --golangci-lint-config=./.golangci.yaml ./cmd/... ./pkg/... ./test/...
	@bash $(GARDENER_HACK_DIR)/check-charts.sh ./charts

.PHONY: generate
generate: $(GEN_CRD_API_REFERENCE_DOCS) $(HELM) $(MOCKGEN) $(YQ) $(VGOPATH)
	@VGOPATH=$(VGOPATH) REPO_ROOT=$(REPO_ROOT) GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) \
		bash $(GARDENER_HACK_DIR)/generate-sequential.sh ./charts/... ./cmd/... ./pkg/... ./test/...
	@$(HACK_DIR)/set-controller-deployment-policy-to-always.sh

.PHONY: format
format: $(GOIMPORTSREVISER)
	@GOIMPORTS_REVISER_OPTIONS="-imports-order std,project,general,company" \
		bash $(GARDENER_HACK_DIR)/format.sh ./cmd ./pkg ./test

.PHONY: test
test: $(REPORT_COLLECTOR)
	@SKIP_FETCH_TOOLS=1 bash $(GARDENER_HACK_DIR)/test.sh ./cmd/... ./pkg/...

.PHONY: test-cov
test-cov:
	@SKIP_FETCH_TOOLS=1 bash $(GARDENER_HACK_DIR)/test-cover.sh ./cmd/... ./pkg/...

.PHONY: test-clean
test-clean:
	@bash $(GARDENER_HACK_DIR)/test-cover-clean.sh

.PHONY: verify
verify: check format test

.PHONY: verify-extended
verify-extended: check-generate check format test test-cov test-clean

.PHONY: update-skaffold-deps
update-skaffold-deps: $(YQ)
	@GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) $(HACK_DIR)/check-skaffold-deps.sh update

# speed-up skaffold deployments by building all images concurrently
export SKAFFOLD_BUILD_CONCURRENCY = 0
extension-up extension-dev: export SKAFFOLD_DEFAULT_REPO = localhost:5001
extension-up extension-dev: export SKAFFOLD_PUSH = true
# use static label for skaffold to prevent rolling all gardener components on every `skaffold` invocation
extension-up extension-dev extension-down: export SKAFFOLD_LABEL = skaffold.dev/run-id=extension-local

extension-up: $(SKAFFOLD) $(KIND) $(HELM) $(KUBECTL) $(CRANE)
	@LD_FLAGS=$(LD_FLAGS) $(SKAFFOLD) --cache-artifacts=false run

extension-dev: $(SKAFFOLD) $(HELM) $(KUBECTL) $(CRANE)
	$(SKAFFOLD) dev --cleanup=false --trigger=manual

extension-down: $(SKAFFOLD) $(HELM) $(KUBECTL)
	$(SKAFFOLD) delete

