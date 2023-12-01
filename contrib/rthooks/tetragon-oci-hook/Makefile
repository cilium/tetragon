# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

GO ?= go

all: tetragon-oci-hook

tetragon-oci-hook: FORCE
	$(GO) build -o $@ ./cmd/hook

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

FORCE:
