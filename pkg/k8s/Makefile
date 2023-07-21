GO ?= go

all: generate

.PHONY: generate

.PHONY: help
help:
	@echo 'Generated files:'
	@echo '    generate          - genereate kubebuilder files'

generate:
	./tools/controller-gen crd paths=./apis/... output:dir=apis/cilium.io/client/crds/v1alpha1
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

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
