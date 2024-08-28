# renovate: datasource=docker
BUILDER_IMAGE=docker.io/library/golang:1.22.6@sha256:2bd56f00ff47baf33e64eae7996b65846c7cb5e0a46e0a882ef179fd89654afa
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
	chmod +x vendor/k8s.io/code-generator/generate-internal-groups.sh
	# Do two invocations of generate-groups.sh, one with --plural-exceptions, one without
	export GOPATH=$$(go env GOPATH); \
	  bash vendor/k8s.io/code-generator/generate-groups.sh deepcopy,defaulter \
	  github.com/cilium/tetragon/pkg/k8s/client \
	  github.com/cilium/tetragon/pkg/k8s/apis \
	  cilium.io:v1alpha1 \
	  --go-header-file hack/custom-boilerplate.go.txt \
	  -o . \
	  --trim-path-prefix github.com/cilium/tetragon/pkg/k8s \
	  ; \
	  bash vendor/k8s.io/code-generator/generate-groups.sh lister,informer,client \
	  github.com/cilium/tetragon/pkg/k8s/client \
	  github.com/cilium/tetragon/pkg/k8s/apis \
	  cilium.io:v1alpha1 \
	  --go-header-file hack/custom-boilerplate.go.txt \
	  -o . \
	  --trim-path-prefix github.com/cilium/tetragon/pkg/k8s \
	  --plural-exceptions TracingPolicyNamespaced:TracingPoliciesNamespaced \
	  --plural-exceptions PodInfo:PodInfo \

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
