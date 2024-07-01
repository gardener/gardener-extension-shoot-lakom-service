# SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

COSIGN         := $(TOOLS_BIN_DIR)/cosign
COSIGN_VERSION ?= v2.2.3
CRANE          := $(TOOLS_BIN_DIR)/crane
CRANE_VERSION  ?= v0.19.2

export TOOLS_BIN_DIR := $(TOOLS_BIN_DIR)
export PATH := $(abspath $(TOOLS_BIN_DIR)):$(PATH)

#########################################
# Common                                #
#########################################

# Use this "function" to add the version file as a prerequisite for the tool target: e.g.
#   $(HELM): $(call tool_version_file,$(HELM),$(HELM_VERSION))
tool_version_file = $(TOOLS_BIN_DIR)/.version_$(subst $(TOOLS_BIN_DIR)/,,$(1))_$(2)

#########################################
# Tools                                 #
#########################################

$(COSIGN): $(call tool_version_file,$(COSIGN),$(COSIGN_VERSION))
	GOBIN=$(abspath $(TOOLS_BIN_DIR)) go install github.com/sigstore/cosign/v2/cmd/cosign@$(COSIGN_VERSION)

$(CRANE): $(call tool_version_file,$(CRANE),$(CRANE_VERSION))
	GOBIN=$(abspath $(TOOLS_BIN_DIR)) go install github.com/google/go-containerregistry/cmd/crane@$(CRANE_VERSION)

