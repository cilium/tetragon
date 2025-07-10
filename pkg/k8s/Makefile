# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.23.11@sha256:eea67064303df95be6d972549b76fafb0372befe7c70dbb178dabad0e2ca378f
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
