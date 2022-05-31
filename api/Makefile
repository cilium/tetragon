# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

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
