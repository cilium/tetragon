GO ?= go
VERSION=$(shell git describe --tags --always)
GO_GCFLAGS ?= ""
GO_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)'"
GO_IMAGE_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)' -linkmode external -extldflags -static"
GO_OPERATOR_IMAGE_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)' -s -w"

GOLANGCILINT_WANT_VERSION = 1.50.1
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)

all: generate

.PHONY: generate

.PHONY: help
help:
	@echo 'Generated files:'
	@echo '    generate          - genereate kubebuilder files'

ifeq (1,$(NOOPT))
GO_GCFLAGS = "all=-N -l"
endif

generate:
	./tools/controller-gen crd paths=./apis/... output:dir=apis/cilium.io/client/crds/v1alpha1
	export GOPATH=$$(go env GOPATH); \
	  bash vendor/k8s.io/code-generator/generate-groups.sh all \
	  github.com/cilium/tetragon/pkg/k8s/client \
	  github.com/cilium/tetragon/pkg/k8s/apis \
	  cilium.io:v1alpha1 \
	  --go-header-file hack/custom-boilerplate.go.txt

.PHONY: vendor
vendor:
	$(GO) mod tidy -compat=1.18
	$(GO) mod vendor
	$(GO) mod verify
