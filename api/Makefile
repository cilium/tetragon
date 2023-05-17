# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

GO ?= go
BUILDER_IMAGE=cilium/tetragon-codegen:latest

.PHONY: all
all: proto

.PHONY: proto
proto: v1

.PHONY: v1
v1:
	docker container run --rm \
		--volume $(CURDIR)/v1:/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(BUILDER_IMAGE) \
		make -C /src -f Makefile.protoc
	./export-docs.sh ../docs/content/en/docs/reference/grpc-api.md

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
