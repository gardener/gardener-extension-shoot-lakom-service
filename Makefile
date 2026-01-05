# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

ENSURE_GARDENER_MOD         := $(shell go get github.com/gardener/gardener@$$(go list -m -f "{{.Version}}" github.com/gardener/gardener))
GARDENER_HACK_DIR           := $(shell go list -m -f "{{.Dir}}" github.com/gardener/gardener)/hack
EXTENSION_PREFIX            := gardener-extension
EXTENSION_NAME              := shoot-lakom-service
SHOOT_ADMISSION_NAME        := shoot-lakom-admission
EXTENSION_FULL_NAME         := $(EXTENSION_PREFIX)-$(EXTENSION_NAME)
SHOOT_ADMISSION_FULL_NAME   := $(EXTENSION_PREFIX)-$(SHOOT_ADMISSION_NAME)
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

export EXTENSION_LD_FLAGS := -w $(shell bash $(GARDENER_HACK_DIR)/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION $(EXTENSION_NAME))
export ADMISSION_LD_FLAGS := -w $(shell bash $(GARDENER_HACK_DIR)/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION $(ADMISSION_NAME))
export SHOOT_ADMISSION_LD_FLAGS := -w $(shell bash $(GARDENER_HACK_DIR)/get-build-ld-flags.sh k8s.io/component-base $(REPO_ROOT)/VERSION $(SHOOT_ADMISSION_NAME))

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
		--lakom-config-path=example/lakom/cosign/config.yaml \
		--cache-ttl=$(CACHE_TTL) \
		--cache-refresh-interval=$(CACHE_REFRESH_INTERVAL)

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
	@LD_FLAGS="$(EXTENSION_LD_FLAGS)" \
		bash $(GARDENER_HACK_DIR)/install.sh ./cmd/$(EXTENSION_FULL_NAME)
	@LD_FLAGS="$(ADMISSION_LD_FLAGS)" \
		bash $(GARDENER_HACK_DIR)/install.sh ./cmd/$(ADMISSION_NAME)
	@LD_FLAGS="$(SHOOT_ADMISSION_LD_FLAGS)" \
		bash $(GARDENER_HACK_DIR)/install.sh ./cmd/$(SHOOT_ADMISSION_FULL_NAME)

.PHONY: docker-images
docker-images:
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) --build-arg TARGETARCH=$(GOARCH) -t $(IMAGE_PREFIX)/$(EXTENSION_NAME):$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(EXTENSION_NAME):latest -f Dockerfile -m 6g --target $(EXTENSION_FULL_NAME) .
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) --build-arg TARGETARCH=$(GOARCH) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(ADMISSION_NAME):latest -f Dockerfile -m 6g --target $(ADMISSION_NAME) .
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) --build-arg TARGETARCH=$(GOARCH) -t $(IMAGE_PREFIX)/$(SHOOT_ADMISSION_NAME):$(EFFECTIVE_VERSION) -t $(IMAGE_PREFIX)/$(SHOOT_ADMISSION_NAME):latest -f Dockerfile -m 6g --target $(SHOOT_ADMISSION_FULL_NAME) .

#####################################################################
# Rules for verification, formatting, linting, testing and cleaning #
#####################################################################

.PHONY: tidy
tidy:
	@go mod tidy
	@cp $(GARDENER_HACK_DIR)/cherry-pick-pull.sh $(HACK_DIR)/cherry-pick-pull.sh && chmod +xw $(HACK_DIR)/cherry-pick-pull.sh

.PHONY: clean
clean:
	@$(shell find ./example -type f -name "controller-registration.yaml" -exec rm '{}' \;)
	@bash $(GARDENER_HACK_DIR)/clean.sh ./cmd/... ./pkg/... ./test/...

.PHONY: check-generate
check-generate:
	@bash $(GARDENER_HACK_DIR)/check-generate.sh $(REPO_ROOT)

.PHONY: check
check: $(GOIMPORTS) $(GOLANGCI_LINT) $(HELM) $(YQ)
	@GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) REPO_ROOT=$(REPO_ROOT) $(HACK_DIR)/generate-golangci-config-file.sh
	@bash $(GARDENER_HACK_DIR)/check.sh --golangci-lint-config=./.golangci.yaml ./cmd/... ./pkg/... ./test/...
	@bash $(GARDENER_HACK_DIR)/check-charts.sh ./charts
	@GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) $(HACK_DIR)/check-skaffold-deps.sh

.PHONY: generate
generate: $(GEN_CRD_API_REFERENCE_DOCS) $(EXTENSION_GEN) $(HELM) $(KUSTOMIZE) $(MOCKGEN) $(YQ) $(VGOPATH)
	@VGOPATH=$(VGOPATH) REPO_ROOT=$(REPO_ROOT) GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) \
		bash $(GARDENER_HACK_DIR)/generate-sequential.sh ./charts/... ./cmd/... ./example/... ./pkg/... ./test/...
	@$(HACK_DIR)/set-controller-deployment-policy-to-always.sh
	$(MAKE) format

.PHONY: format
format: $(GOIMPORTS) $(GOIMPORTSREVISER)
	@GOIMPORTS_REVISER_OPTIONS="-imports-order std,project,general,company" \
		bash $(GARDENER_HACK_DIR)/format.sh ./cmd ./pkg ./test ./charts

.PHONY: sast
sast: $(GOSEC)
	@bash $(GARDENER_HACK_DIR)/sast.sh

.PHONY: sast-report
sast-report: $(GOSEC)
	@bash $(GARDENER_HACK_DIR)/sast.sh --gosec-report true

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
verify: check format test sast

.PHONY: verify-extended
verify-extended: check-generate check format test test-cov test-clean sast-report

.PHONY: update-skaffold-deps
update-skaffold-deps: $(YQ)
	@GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) $(HACK_DIR)/check-skaffold-deps.sh update

# speed-up skaffold deployments by building all images concurrently
export SKAFFOLD_BUILD_CONCURRENCY = 0
extension-up extension-dev extension-operator-up: export SKAFFOLD_DEFAULT_REPO = registry.local.gardener.cloud:5001
extension-up extension-dev extension-operator-up: export SKAFFOLD_PUSH = true
# use static label for skaffold to prevent rolling all gardener components on every `skaffold` invocation
extension-up extension-dev extension-down extension-operator-up extension-operator-down: export SKAFFOLD_LABEL = skaffold.dev/run-id=extension-local

extension-up: $(SKAFFOLD) $(KIND) $(HELM) $(KUBECTL) $(CRANE)
	$(SKAFFOLD) --cache-artifacts=false run

extension-dev: $(SKAFFOLD) $(HELM) $(KUBECTL) $(CRANE) $(KIND)
	$(SKAFFOLD) dev --cleanup=false --trigger=manual

extension-down: $(SKAFFOLD) $(HELM) $(KUBECTL)
	$(SKAFFOLD) delete

extension-operator-up extension-operator-down: export SKAFFOLD_FILENAME = skaffold-operator.yaml
extension-operator-up: $(SKAFFOLD) $(KIND) $(HELM) $(KUBECTL)
	@GARDENER_HACK_DIR=$(GARDENER_HACK_DIR) EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) \
		$(SKAFFOLD) --cache-artifacts=false run

extension-operator-down: $(SKAFFOLD) $(HELM) $(KUBECTL)
	$(SKAFFOLD) delete
