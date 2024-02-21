# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# renovate: datasource=docker
BUILDER_IMAGE=quay.io/cilium/cilium-builder@sha256:a2036a3f6420647e6702695dabd2ffa4d2832db45157042d0255bdc707b8e1f2
GO ?= go

.PHONY: all
all: proto

.PHONY: proto
proto: v1

.PHONY: v1
v1:
	docker container run --rm \
		--volume $(CURDIR)/..:/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(BUILDER_IMAGE) \
		make -C /src/api/v1 -f Makefile.protoc
	./export-docs.sh ../docs/content/en/docs/reference/grpc-api.md

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
