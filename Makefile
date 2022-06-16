GO ?= go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest
LOCAL_CLANG ?= 0
LOCAL_CLANG_FORMAT ?= 0
FORMAT_FIND_FLAGS ?= -name '*.c' -o -name '*.h' -not -path 'bpf/include/vmlinux.h' -not -path 'bpf/include/api.h' -not -path 'bpf/libbpf/*'
NOOPT ?= 0
LIBBPF_IMAGE = quay.io/isovalent/hubble-libbpf:v0.2.3
CLANG_IMAGE  = quay.io/isovalent/hubble-llvm:2020-12-29-45f6aa2
METADATA_IMAGE = quay.io/isovalent/tetragon-metadata
TESTER_PROGS_DIR = "contrib/tester-progs"

LIBBPF_INSTALL_DIR ?= ./lib
CLANG_INSTALL_DIR  ?= ./bin
VERSION=$(shell git describe --tags --always)
GO_GCFLAGS ?= ""
GO_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)'"
GO_IMAGE_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)' -linkmode external -extldflags -static"
GO_OPERATOR_IMAGE_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)' -s -w"


GOLANGCILINT_WANT_VERSION = 1.45.2
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)


all: tetragon-bpf tetragon tetra tetragon-alignchecker test-compile tester-progs

.PHONY: tetragon-bpf tetragon-bpf-local tetragon-bpf-container tester-progs

-include Makefile.docker

ifeq (1,$(LOCAL_CLANG))
tetragon-bpf: tetragon-bpf-local
else
tetragon-bpf: tetragon-bpf-container
endif

ifeq (1,$(NOOPT))
GO_GCFLAGS = "all=-N -l"
endif

tetragon-bpf-local:
	$(MAKE) -C ./bpf

verify: tetragon-bpf
	sudo contrib/verify/verify.sh bpf/objs

tetragon-bpf-container:
	$(CONTAINER_ENGINE) rm hubble-llvm || true
	$(CONTAINER_ENGINE) run -v $(CURDIR):/tetragon -u $$(id -u)  --name hubble-llvm $(CLANG_IMAGE) $(MAKE) -C /tetragon/bpf
	$(CONTAINER_ENGINE) rm hubble-llvm

tetragon:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor ./cmd/tetragon/

tetra:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor ./cmd/tetra/

tetragon-operator:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor -o $@ ./operator

tetragon-alignchecker:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor -o $@ ./tools/alignchecker/

.PHONY: ksyms
ksyms:
	$(GO) build ./cmd/ksyms/

tetragon-image:
	GOOS=linux GOARCH=amd64 $(GO) build -tags netgo -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/tetragon/
	GOOS=linux GOARCH=amd64 $(GO) build -tags netgo -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/tetra/

tetragon-operator-image:
	CGO_ENABLED=0 $(GO) build -ldflags=$(GO_OPERATOR_IMAGE_LDFLAGS) -mod=vendor -o tetragon-operator ./operator

install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./tetragon $(DESTDIR)$(BINDIR)

clean:
	$(MAKE) -C ./bpf clean
	rm -f go-tests/*.test ./ksyms ./tetragon ./tetragon-operator ./tetra ./tetragon-alignchecker
	rm -f contrib/sigkill-tester/sigkill-tester contrib/namespace-tester/test_ns contrib/capabilities-tester/test_caps
	$(MAKE) -C $(TESTER_PROGS_DIR) clean

test:
	ulimit -n 1048576 && $(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_GCFLAGS) -timeout 20m -failfast -cover ./...

test-compile:
	mkdir -p go-tests
	for pkg in $$($(GO) list ./...); do \
		localpkg=$$(echo $$pkg | sed -e 's:github.com/cilium/tetragon/::'); \
		localtestfile=$$(echo $$localpkg | sed -e 's:/:.:g'); \
		echo -c ./$$localpkg -o go-tests/$$localtestfile; \
	done | xargs -P $$(nproc) -L 1 $(GO) test -gcflags=$(GO_GCFLAGS)

.PHONY: check-copyright update-copyright
check-copyright:
	for dir in $(COPYRIGHT_DIRS); do \
		contrib/copyright-headers check $$dir; \
	done

update-copyright:
	for dir in $(COPYRIGHT_DIRS); do \
		contrib/copyright-headers update $$dir; \
	done

lint:
	golint -set_exit_status $$(go list ./...)

image:
	$(CONTAINER_ENGINE) build -t "cilium/tetragon:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/tetragon:$(DOCKER_IMAGE_TAG)"

image-operator:
	$(CONTAINER_ENGINE) build -f operator.Dockerfile -t "cilium/tetragon-operator:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/tetragon-operator:$(DOCKER_IMAGE_TAG)"

image-test:
	$(CONTAINER_ENGINE) build -f Dockerfile.test -t "cilium/tetragon-test:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/tetragon-test:$(DOCKER_IMAGE_TAG)"

image-codegen:
	$(CONTAINER_ENGINE) build -f Dockerfile.codegen -t "cilium/tetragon-codegen:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/tetragon-codegen:$(DOCKER_IMAGE_TAG)"

.PHONY: tools-install tools-clean libbpf-install clang-install
tools-install: libbpf-install clang-install
tools-clean:
	rm -rf $(LIBBPF_INSTALL_DIR)
	rm -rf $(CLANG_INSTALL_DIR)
libbpf-install:
	$(eval id=$(shell $(CONTAINER_ENGINE) create $(LIBBPF_IMAGE)))
	mkdir -p $(LIBBPF_INSTALL_DIR)
	$(CONTAINER_ENGINE) cp ${id}:/go/src/github.com/covalentio/hubble-fgs/src/libbpf.so $(LIBBPF_INSTALL_DIR)
	$(CONTAINER_ENGINE) cp ${id}:/go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0 $(LIBBPF_INSTALL_DIR)
	$(CONTAINER_ENGINE) cp ${id}:/go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0.2.0 $(LIBBPF_INSTALL_DIR)
	$(CONTAINER_ENGINE) stop ${id}

clang-install:
	$(eval id=$(shell $(CONTAINER_ENGINE) create $(CLANG_IMAGE)))
	mkdir -p $(CLANG_INSTALL_DIR)
	$(CONTAINER_ENGINE) cp ${id}:/usr/local/bin/clang-11 $(CLANG_INSTALL_DIR)/clang
	$(CONTAINER_ENGINE) cp ${id}:/usr/local/bin/llc $(CLANG_INSTALL_DIR)/llc
	$(CONTAINER_ENGINE) stop ${id}

generate:
	./tools/controller-gen crd paths=./pkg/k8s/apis/... output:dir=pkg/k8s/apis/cilium.io/client/crds/v1alpha1
	export GOPATH=$$(go env GOPATH); \
	  bash vendor/k8s.io/code-generator/generate-groups.sh all \
	  github.com/cilium/tetragon/pkg/k8s/client \
	  github.com/cilium/tetragon/pkg/k8s/apis \
	  cilium.io:v1alpha1 \
	  --go-header-file hack/custom-boilerplate.go.txt

codegen: image-codegen
	$(MAKE) -C api

ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
check:
	golangci-lint run
else
check:
	$(CONTAINER_ENGINE) build -t golangci-lint:tetragon . -f Dockerfile.golangci-lint
	$(CONTAINER_ENGINE) run --rm -v `pwd`:/app -w /app golangci-lint:tetragon golangci-lint run
endif

.PHONY: clang-format
ifeq (1,$(LOCAL_CLANG_FORMAT))
clang-format:
	find bpf $(FORMAT_FIND_FLAGS) | xargs -n 1000 clang-format -i -style=file
else
clang-format:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang-format -t "cilium/clang-format:${DOCKER_IMAGE_TAG}" .
	find bpf $(FORMAT_FIND_FLAGS) | xargs -n 1000 \
		$(CONTAINER_ENGINE) run -v $(shell realpath .):/tetragon "cilium/clang-format:${DOCKER_IMAGE_TAG}" -i -style=file
endif

.PHONY: go-format
go-format:
	find . -name '*.go' -not -path './vendor/*' | xargs gofmt -w

.PHONY: format
format: go-format clang-format

.PHONY: headers all clean image install lint tetragon tetra generate check


# generate cscope for bpf files
cscope:
	find bpf -name "*.[chxsS]" -print > cscope.files
	cscope -b -q -k
.PHONY: cscope

tester-progs:
	$(MAKE) -C $(TESTER_PROGS_DIR)
.PHONY: tester-progs
