GO ?= go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest
LOCAL_CLANG ?= 0
LOCAL_CLANG_FORMAT ?= 0
FORMAT_FIND_FLAGS ?= -name '*.c' -o -name '*.h' -not -path 'bpf/include/vmlinux.h' -not -path 'bpf/include/api.h' -not -path 'bpf/libbpf/*'
NOOPT ?= 0
CLANG_IMAGE  = quay.io/cilium/clang:7ea8dd5b610a8864ce7b56e10ffeb61030a0c50e@sha256:02ad7cc1d08d85c027557099b88856945be5124b5c31aeabce326e7983e3913b
METADATA_IMAGE = quay.io/isovalent/tetragon-metadata
TESTER_PROGS_DIR = "contrib/tester-progs"
# Extra flags to pass to test binary
EXTRA_TESTFLAGS ?=

VERSION=$(shell git describe --tags --always)
GO_GCFLAGS ?= ""
GO_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)'"
GO_IMAGE_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)' -linkmode external -extldflags -static"
GO_OPERATOR_IMAGE_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)' -s -w"


GOLANGCILINT_WANT_VERSION = 1.45.2
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)


all: tetragon-bpf tetragon tetra tetragon-alignchecker test-compile tester-progs protoc-gen-go-tetragon

.PHONY: tetragon-bpf tetragon-bpf-local tetragon-bpf-container tester-progs protoc-gen-go-tetragon

-include Makefile.docker

.PHONY: help
help:
	@echo 'Installation:'
	@echo '    install           - install tetragon agent and tetra as standalone binaries'
	@echo 'Compilation:'
	@echo '    tetragon          - compile the Tetragon agent'
	@echo '    tetragon-operator - compile the Tetragon operator'
	@echo '    tetra             - compile the Tetragon gRPC client'
	@echo '    tetragon-bpf      - compile bpf programs (use LOCAL_CLANG=0 to compile in a Docker build env)'
	@echo '    test-compile      - compile unit tests'
	@echo '    tester-progs      - compile helper programs for unit testing'
	@echo 'Container images:'
	@echo '    image             - build the Tetragon agent container image'
	@echo '    image-operator    - build the Tetragon operator container image'
	@echo 'Generated files:'
	@echo '    codegen           - genereate code based on .proto files'
	@echo '    generate          - genereate kubebuilder files'
	@echo 'Linting and chores:'
	@echo '    vendor            - tidy and vendor Go modules'
	@echo '    clang-format      - run code formatter on BPF code'
	@echo '    go-format         - run code formatter on Go code'
	@echo '    format            - convenience alias for clang-format and go-format'

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
	$(CONTAINER_ENGINE) rm tetragon-clang || true
	$(CONTAINER_ENGINE) run -v $(CURDIR):/tetragon -u $$(id -u) --name tetragon-clang $(CLANG_IMAGE) $(MAKE) -C /tetragon/bpf
	$(CONTAINER_ENGINE) rm tetragon-clang

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

.PHONY: vendor
vendor:
	$(MAKE) -C ./api vendor
	$(MAKE) -C ./pkg/k8s vendor
	$(GO) mod tidy -compat=1.17
	$(GO) mod vendor
	$(GO) mod verify

clean:
	$(MAKE) -C ./bpf clean
	rm -f go-tests/*.test ./ksyms ./tetragon ./tetragon-operator ./tetra ./tetragon-alignchecker
	rm -f contrib/sigkill-tester/sigkill-tester contrib/namespace-tester/test_ns contrib/capabilities-tester/test_caps
	$(MAKE) -C $(TESTER_PROGS_DIR) clean

.PHONY: test
test:
	ulimit -n 1048576 && $(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_GCFLAGS) -timeout 20m -failfast -cover ./pkg/... ${EXTRA_TESTFLAGS}


.PHONY: e2e-test
e2e-test: image image-operator
	$(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_GCFLAGS) -timeout 20m -failfast -cover ./tests/e2e/tests/... ${EXTRA_TESTFLAGS} -fail-fast -tetragon.helm.set tetragon.image.override="cilium/tetragon:${DOCKER_IMAGE_TAG}" -tetragon.helm.set tetragonOperator.image.override="cilium/tetragon-operator:${DOCKER_IMAGE_TAG}" -tetragon.helm.url="" -tetragon.helm.chart="$(realpath ./install/kubernetes)"

test-compile:
	mkdir -p go-tests
	for pkg in $$($(GO) list ./...); do \
		localpkg=$$(echo $$pkg | sed -e 's:github.com/cilium/tetragon/::'); \
		localtestfile=$$(echo $$localpkg | sed -e 's:/:.:g'); \
		numtests=$$(ls -l ./$$localpkg/*_test.go 2> /dev/null | wc -l); \
		if [ $$numtests -le 0 ]; then \
			continue; \
		fi; \
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

image: image-clang
	$(CONTAINER_ENGINE) build -t "cilium/tetragon:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/tetragon:$(DOCKER_IMAGE_TAG)"

image-operator:
	$(CONTAINER_ENGINE) build -f operator.Dockerfile -t "cilium/tetragon-operator:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/tetragon-operator:$(DOCKER_IMAGE_TAG)"

image-test: image-clang
	$(CONTAINER_ENGINE) build -f Dockerfile.test -t "cilium/tetragon-test:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/tetragon-test:$(DOCKER_IMAGE_TAG)"

image-codegen:
	$(CONTAINER_ENGINE) build -f Dockerfile.codegen -t "cilium/tetragon-codegen:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/tetragon-codegen:$(DOCKER_IMAGE_TAG)"

.PHONY: image-clang
image-clang:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang -t "cilium/clang:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/clang:$(DOCKER_IMAGE_TAG)"

fetch-testdata:
	wget -nc -P testdata/btf 'https://github.com/cilium/tetragon-testdata/raw/main/btf/vmlinux-5.4.104+'

generate:
	# Need to call vendor twice here, once before and once after generate, the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) vendor
	$(MAKE) -C pkg/k8s/
	$(MAKE) vendor

codegen: image-codegen
	# Need to call vendor twice here, once before and once after codegen the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) vendor
	$(MAKE) -C api
	$(MAKE) vendor

protoc-gen-go-tetragon:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor -o bin/$@ ./cmd/protoc-gen-go-tetragon/

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
	find . -name '*.go' -not -path './vendor/*' -not -path './api/vendor/*' -not -path './pkg/k8s/vendor/*' | xargs gofmt -w

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
