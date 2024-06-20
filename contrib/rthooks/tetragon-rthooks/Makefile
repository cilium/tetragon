# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

GO ?= go

all: tetragon-oci-hook tetragon-oci-hook-setup

images: setup-image setup-image-debug

.PHONY: setup-image
setup-image:
	docker build . -f dockerfiles/setup -t quay.io/isovalent/tetragon-oci-hook-setup:latest

.PHONY: setup-image-debug
setup-image-debug:
	docker build . -f dockerfiles/setup --build-arg BASE_IMAGE=ubuntu -t quay.io/isovalent/tetragon-oci-hook-setup:debug-latest

tetragon-oci-hook-setup: FORCE
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/setup

tetragon-oci-hook: FORCE
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/hook

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

FORCE:
