# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.23.2@sha256:cc637ce72c1db9586bd461cc5882df5a1c06232fd5dfe211d3b32f79c5a999fc
GO ?= go

all: generate

.PHONY: help
help:
	@echo 'Generated files:'
	@echo '    generate          - generate kubebuilder files'

.PHONY: generate
generate:
	docker container run --rm \
		--volume $(CURDIR)/../..:/src \
		--user "$(shell id -u):$(shell id -g)" \
		--env GOCACHE=/go/.cache \
		$(BUILDER_IMAGE) \
		make -C /src/pkg/k8s __do_generate

.PHONY: __do_generate
__do_generate:
	./tools/controller-gen crd paths=./apis/... output:dir=apis/cilium.io/client/crds/v1alpha1
	./tools/k8s-code-gen.sh

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
