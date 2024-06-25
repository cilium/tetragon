# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

GO ?= go

progs = tetragon-oci-hook \
	tetragon-oci-hook-setup \
	tetragon-nri-hook

all: $(progs)

tetragon-oci-hook-setup: FORCE
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/setup

tetragon-oci-hook: FORCE
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/oci-hook

tetragon-nri-hook: FORCE
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/nri-hook

clean:
	rm -f $(progs)

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

FORCE:
