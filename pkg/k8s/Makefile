# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.23.4@sha256:574185e5c6b9d09873f455a7c205ea0514bfd99738c5dc7750196403a44ed4b7
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
