GO ?= go
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest
LOCAL_CLANG ?= 0
LOCAL_CLANG_FORMAT ?= 0
FORMAT_FIND_FLAGS ?= -name '*.c' -o -name '*.h' -not -path 'bpf/include/vmlinux.h' -not -path 'bpf/include/api.h' -not -path 'bpf/libbpf/*'
NOOPT ?= 0
CLANG_IMAGE = quay.io/cilium/clang:aeaada5cf60efe8d0e772d032fe3cc2bc613739c@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f
TESTER_PROGS_DIR = "contrib/tester-progs"
# Extra flags to pass to test binary
EXTRA_TESTFLAGS ?=
SUDO ?= sudo
GO_TEST_TIMEOUT ?= 20m
E2E_TEST_TIMEOUT ?= 20m
BUILD_PKG_DIR ?= $(shell pwd)/build/$(TARGET_ARCH)
VERSION ?= $(shell git describe --tags --always)

# Do a parallel build with multiple jobs, based on the number of CPUs online
# in this system: 'make -j8' on a 8-CPU system, etc.
#
# (To override it, run 'make JOBS=1' and similar.)
JOBS ?= $(shell nproc)

# Detect architecture, use TARGET_ARCH=amd64 or TARGET_ARCH=arm64
# or let uname detect the appropriate arch for native build
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	TARGET_ARCH ?= amd64
endif
ifeq ($(UNAME_M),aarch64)
	TARGET_ARCH ?= arm64
endif
ifeq ($(UNAME_M),arm64)
	TARGET_ARCH ?= arm64
endif
TARGET_ARCH ?= amd64

# Set GOARCH to TARGET_ARCH only if it's not set so that we can still use both
# GOARCH and TARGET_ARCH (make sense for pure Go program like tetragon-operator)
GOARCH ?= $(TARGET_ARCH)

# Set BPF_TARGET_ARCH using TARGET_ARCH
ifeq ($(TARGET_ARCH),amd64)
	BPF_TARGET_ARCH ?= x86
endif
ifeq ($(TARGET_ARCH),arm64)
	BPF_TARGET_ARCH ?= arm64
endif
BPF_TARGET_ARCH ?= x86

__BPF_DEBUG_FLAGS :=
ifeq ($(DEBUG),1)
	NOOPT=1
	NOSTRIP=1
	__BPF_DEBUG_FLAGS += DEBUG=1
endif

# GO_BUILD_LDFLAGS is initialized to empty use EXTRA_GO_BUILD_LDFLAGS to add link flags
GO_BUILD_LDFLAGS =
GO_BUILD_LDFLAGS += -X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)'
ifeq ($(NOSTRIP),)
    # Note: these options will not remove annotations needed for stack
    # traces, so panic backtraces will still be readable.
    # -w: Omit the DWARF symbol table.
    # -s: Omit the symbol table and debug information.
    GO_BUILD_LDFLAGS += -s -w
endif
ifdef EXTRA_GO_BUILD_LDFLAGS
	GO_BUILD_LDFLAGS += $(EXTRA_GO_BUILD_LDFLAGS)
endif

# GO_BUILD_FLAGS is initialized to empty use EXTRA_GO_BUILD_FLAGS to add build flags
GO_BUILD_FLAGS =
GO_BUILD_FLAGS += -ldflags "$(GO_BUILD_LDFLAGS)"
ifeq ($(NOOPT),1)
	GO_BUILD_GCFLAGS = "all=-N -l"
    GO_BUILD_FLAGS += -gcflags=$(GO_BUILD_GCFLAGS)
endif
GO_BUILD_FLAGS += -mod=vendor
ifdef EXTRA_GO_BUILD_FLAGS
	GO_BUILD_FLAGS += $(EXTRA_GO_BUILD_FLAGS)
endif

GO_BUILD = CGO_ENABLED=0 GOARCH=$(GOARCH) $(GO) build $(GO_BUILD_FLAGS)
GO_BUILD_HOOK = CGO_ENABLED=0 GOARCH=$(GOARCH) $(GO) -C contrib/rthooks/tetragon-oci-hook build $(GO_BUILD_FLAGS)

.PHONY: all
all: tetragon-bpf tetragon tetra generate-flags test-compile tester-progs protoc-gen-go-tetragon tetragon-bench

-include Makefile.docker
-include Makefile.cli

.PHONY: help
help:
	@echo 'Targets:'
	@echo '    Installation:'
	@echo '        install           - install tetragon agent and tetra as standalone binaries'
	@echo '    Compilation:'
	@echo '        tetragon          - compile the Tetragon agent'
	@echo '        tetragon-operator - compile the Tetragon operator'
	@echo '        tetra             - compile the Tetragon gRPC client'
	@echo '        tetragon-bpf      - compile bpf programs (use LOCAL_CLANG=0 to compile in a Docker build env)'
	@echo '        test-compile      - compile unit tests'
	@echo '        tester-progs      - compile helper programs for unit testing'
	@echo '        compile-commands  - generate a compile_commands.json with bear for bpf programs'
	@echo '        cli-release       - compile tetra CLI release binaries'
	@echo '    Container images:'
	@echo '        image             - build the Tetragon agent container image'
	@echo '        image-operator    - build the Tetragon operator container image'
	@echo '    Packages:'
	@echo '        tarball           - build Tetragon compressed tarball'
	@echo '        tarball-release   - build Tetragon release tarball'
	@echo '    Generated files:'
	@echo '        protogen          - generate code based on .proto files'
	@echo '        crds              - generate kubebuilder files'
	@echo '        generate-flags    - generate Tetragon daemon flags for documentation'
	@echo '    Linting and chores:'
	@echo '        vendor            - tidy and vendor Go modules'
	@echo '        clang-format      - run code formatter on BPF code'
	@echo '        go-format         - run code formatter on Go code'
	@echo '        format            - convenience alias for clang-format and go-format'
	@echo '        lint-metrics-md   - check if metrics documentation is up to date'
	@echo '    Documentation:'
	@echo '        docs              - preview documentation website'
	@echo '        metrics-docs      - generate metrics reference documentation page'
	@echo 'End-to-end tests: '
	@echo '    e2e-test                                        - run e2e tests'
	@echo '    e2e-test E2E_BUILD_IMAGES=0                     - run e2e tests without (re-)building images'
	@echo '    e2e-test E2E_TESTS=./tests/e2e/tests/skeleton   - run a specific e2e test'
	@echo 'Options:'
	@echo '    TARGET_ARCH            - target architecture to build for (e.g. amd64 or arm64)'
	@echo '    BPF_TARGET_ARCH        - target architecture for BPF progs, set by TARGET_ARCH'
	@echo '    GO_ARCH                - target architecture for Go progs, set by TARGET_ARCH'
	@echo '    DEBUG                  - enable NOOPT and NOSTRIP'
	@echo '    NOOPT                  - disable optimization in Go build, set by DEBUG'
	@echo '    NOSTRIP                - disable binary stripping in Go build, set by DEBUG'
	@echo '    LOCAL_CLANG            - use the local clang install for BPF compilation'
	@echo '    JOBS                   - number of jobs to run for BPF compilation (default to nproc)'
	@echo '    EXTRA_GO_BUILD_LDFLAGS - extra flags to pass to the Go linker'
	@echo '    EXTRA_GO_BUILD_FLAGS   - extra flags to pass to the Go builder'
	@echo '    EXTRA_GO_BUILD_FLAGS   - extra flags to pass to the Go builder'

# Generate compile-commands.json using bear
.PHONY: compile-commands
compile-commands:
	$(MAKE) -C ./bpf clean
	bear -- $(MAKE) -C ./bpf

.PHONY: tetragon-bpf tetragon-bpf-local tetragon-bpf-container
ifeq (1,$(LOCAL_CLANG))
tetragon-bpf: tetragon-bpf-local
else
tetragon-bpf: tetragon-bpf-container
endif

tetragon-bpf-local:
	$(MAKE) -C ./bpf BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) -j$(JOBS) $(__BPF_DEBUG_FLAGS)

tetragon-bpf-container:
	$(CONTAINER_ENGINE) rm tetragon-clang || true
	$(CONTAINER_ENGINE) run -v $(CURDIR):/tetragon:Z -u $$(id -u) -e BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) --name tetragon-clang $(CLANG_IMAGE) make -C /tetragon/bpf -j$(JOBS) $(__BPF_DEBUG_FLAGS)
	$(CONTAINER_ENGINE) rm tetragon-clang

.PHONY: bpf-test
bpf-test:
	$(MAKE) -C ./bpf run-test

.PHONY: verify
verify: tetragon-bpf
	sudo contrib/verify/verify.sh bpf/objs

.PHONY: generate-flags tetragon tetra tetragon-operator tetragon-bench
generate-flags: tetragon
	echo "$$(./tetragon --generate-docs)" > docs/data/tetragon_flags.yaml

tetragon:
	$(GO_BUILD) ./cmd/tetragon/

tetra:
	$(GO_BUILD) ./cmd/tetra/

tetragon-bench:
	$(GO_BUILD) ./cmd/tetragon-bench/

tetragon-operator:
	$(GO_BUILD) -o $@ ./operator

tetragon-oci-hook:
	$(GO_BUILD_HOOK) -o $@ ./cmd/hook

tetragon-oci-hook-setup:
	$(GO_BUILD_HOOK) -o $@ ./cmd/setup

.PHONY: alignchecker
alignchecker:
	$(GO) test -c ./pkg/alignchecker -o alignchecker

.PHONY: ksyms
ksyms:
	$(GO) build ./cmd/ksyms/

.PHONY: install
install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./tetragon $(DESTDIR)$(BINDIR)

.PHONY: vendor
vendor:
	$(MAKE) -C ./api vendor
	$(MAKE) -C ./pkg/k8s vendor
	$(MAKE) -C ./contrib/rthooks/tetragon-oci-hook vendor
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

.PHONY: clean
clean: cli-clean tarball-clean
	$(MAKE) -C ./bpf clean
	rm -f go-tests/*.test ./ksyms ./tetragon ./tetragon-operator ./tetra ./alignchecker
	rm -f contrib/sigkill-tester/sigkill-tester contrib/namespace-tester/test_ns contrib/capabilities-tester/test_caps
	$(MAKE) -C $(TESTER_PROGS_DIR) clean

.PHONY: test
test: tester-progs tetragon-bpf
	$(GO) test -exec "$(SUDO)" -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(GO_TEST_TIMEOUT) -failfast -cover ./pkg/... ./cmd/... ./operator/... ${EXTRA_TESTFLAGS}

.PHONY: bench
bench:
	$(GO) test -exec "$(SUDO)" -p 1 -parallel 1 -run ^$$ $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(GO_TEST_TIMEOUT) -failfast -cover ./pkg/... ./cmd/... ./operator/... -bench=. ${EXTRA_TESTFLAGS}

# Agent image to use for end-to-end tests
E2E_AGENT ?= "cilium/tetragon:$(DOCKER_IMAGE_TAG)"
# Operator image to use for end-to-end tests
E2E_OPERATOR ?= "cilium/tetragon-operator:$(DOCKER_IMAGE_TAG)"
# BTF file to use in the E2E test. Set to nothing to use system BTF.
E2E_BTF ?= ""
# Actual flags to use for BTF file in e2e test. Use E2E_BTF instead.
ifneq ($(E2E_BTF), "")
	E2E_BTF_FLAGS ?= "-tetragon.btf=$(shell readlink -f $(E2E_BTF))"
else
	E2E_BTF_FLAGS = ""
endif
# Build image and operator images locally before running test. Set to 0 to disable.
E2E_BUILD_IMAGES ?= 1
E2E_TESTS ?= ./tests/e2e/tests/...

# Run an e2e-test
.PHONY: e2e-test
ifneq ($(E2E_BUILD_IMAGES), 0)
e2e-test: image image-operator
else
e2e-test:
endif
	$(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(E2E_TEST_TIMEOUT) -failfast -cover $(E2E_TESTS) ${EXTRA_TESTFLAGS} -fail-fast -tetragon.helm.set tetragon.image.override="$(E2E_AGENT)" -tetragon.helm.set tetragonOperator.image.override="$(E2E_OPERATOR)" -tetragon.helm.url="" -tetragon.helm.chart="$(realpath ./install/kubernetes/tetragon)" $(E2E_BTF_FLAGS)

TEST_COMPILE ?= ./...
.PHONY: test-compile
test-compile:
	mkdir -p go-tests
	for pkg in $$($(GO) list "$(TEST_COMPILE)"); do \
		localpkg=$$(echo $$pkg | sed -e 's:github.com/cilium/tetragon/::'); \
		localtestfile=$$(echo $$localpkg | sed -e 's:/:.:g'); \
		numtests=$$(ls -l ./$$localpkg/*_test.go 2> /dev/null | wc -l); \
		if [ $$numtests -le 0 ]; then \
			continue; \
		fi; \
		echo -c ./$$localpkg -o go-tests/$$localtestfile; \
	done | GOMAXPROCS=1 xargs -P $(JOBS) -L 1 $(GO) test -gcflags=$(GO_BUILD_GCFLAGS)

.PHONY: check-copyright update-copyright
check-copyright:
	for dir in $(COPYRIGHT_DIRS); do \
		contrib/copyright-headers check $$dir; \
	done

update-copyright:
	for dir in $(COPYRIGHT_DIRS); do \
		contrib/copyright-headers update $$dir; \
	done

.PHONY: lint
lint:
	golint -set_exit_status $$(go list ./...)

.PHONY: image image-operator image-test
image:
	$(CONTAINER_ENGINE) build -t "cilium/tetragon:${DOCKER_IMAGE_TAG}" --target release --build-arg TETRAGON_VERSION=$(VERSION) --platform=linux/${TARGET_ARCH} .
	$(QUIET)@echo "Push like this when ready:"
	$(QUIET)@echo "${CONTAINER_ENGINE} push cilium/tetragon:$(DOCKER_IMAGE_TAG)"

image-operator:
	$(CONTAINER_ENGINE) build -f Dockerfile.operator -t "cilium/tetragon-operator:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	$(QUIET)@echo "Push like this when ready:"
	$(QUIET)@echo "${CONTAINER_ENGINE} push cilium/tetragon-operator:$(DOCKER_IMAGE_TAG)"

image-test: image-clang
	$(CONTAINER_ENGINE) build -f Dockerfile.test -t "cilium/tetragon-test:${DOCKER_IMAGE_TAG}" .
	$(QUIET)@echo "Push like this when ready:"
	$(QUIET)@echo "${CONTAINER_ENGINE} push cilium/tetragon-test:$(DOCKER_IMAGE_TAG)"

.PHONY: image-clang
image-clang:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang --build-arg VERSION=1:15.0.7-0ubuntu0.22.04.2 -t "cilium/clang:${DOCKER_IMAGE_TAG}" .
	$(QUIET)@echo "Push like this when ready:"
	$(QUIET)@echo "${CONTAINER_ENGINE} push cilium/clang:$(DOCKER_IMAGE_TAG)"

.PHONY: images
images: image image-operator

.PHONY: tarball tarball-release tarball-clean
# Share same build environment as docker image
# Then it uses docker save to dump the layer and use it to
# contruct the tarball.
# Requires 'jq' to be installed
tarball: tarball-clean image
	$(CONTAINER_ENGINE) build --build-arg TETRAGON_VERSION=$(VERSION) --build-arg TARGET_ARCH=$(TARGET_ARCH) -f Dockerfile.tarball -t "cilium/tetragon-tarball:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)
	$(CONTAINER_ENGINE) save cilium/tetragon-tarball:$(DOCKER_IMAGE_TAG) -o $(BUILD_PKG_DIR)/tetragon-$(VERSION)-$(TARGET_ARCH).tmp.tar
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)/docker/
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)/linux-tarball/
	tar xC $(BUILD_PKG_DIR)/docker/ -f $(BUILD_PKG_DIR)/tetragon-$(VERSION)-$(TARGET_ARCH).tmp.tar
	sync $(BUILD_PKG_DIR)/docker/manifest.json
	cat $(BUILD_PKG_DIR)/docker/manifest.json
	cp "${BUILD_PKG_DIR}/docker/$$(jq -r '.[].Layers[0]' "${BUILD_PKG_DIR}/docker/manifest.json")" ${BUILD_PKG_DIR}/linux-tarball/tetragon-$(VERSION)-$(TARGET_ARCH).tar
	@tar -tf ${BUILD_PKG_DIR}/linux-tarball/tetragon-$(VERSION)-$(TARGET_ARCH).tar | grep "/usr/local/bin/tetragon" - \
		|| (echo "make: '$@' Error: could not find tetragon inside generated tarball"; exit 1)
	$(QUIET)rm -fr $(BUILD_PKG_DIR)/tetragon-$(VERSION)-$(TARGET_ARCH).tmp.tar
	gzip -6 $(BUILD_PKG_DIR)/linux-tarball/tetragon-$(VERSION)-$(TARGET_ARCH).tar
	@echo "Tetragon tarball is ready: $(BUILD_PKG_DIR)/linux-tarball/tetragon-$(VERSION)-$(TARGET_ARCH).tar.gz"

tarball-release: tarball
	mkdir -p release/
	mv $(BUILD_PKG_DIR)/linux-tarball/tetragon-$(VERSION)-$(TARGET_ARCH).tar.gz release/
	(cd release && sha256sum tetragon-$(VERSION)-$(TARGET_ARCH).tar.gz > tetragon-$(VERSION)-$(TARGET_ARCH).tar.gz.sha256sum)

tarball-clean:
	rm -fr $(BUILD_PKG_DIR)

fetch-testdata:
	wget -nc -P testdata/btf 'https://github.com/cilium/tetragon-testdata/raw/main/btf/vmlinux-5.4.104+'

.PHONY: generate crds protogen codegen protoc-gen-go-tetragon
generate: | crds
crds:
	# Need to call vendor twice here, once before and once after generate, the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) vendor
	$(MAKE) -C pkg/k8s/
	$(MAKE) vendor

codegen: | protogen
protogen: protoc-gen-go-tetragon
	# Need to call vendor twice here, once before and once after codegen the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) vendor
	$(MAKE) -C api
	$(MAKE) vendor

protoc-gen-go-tetragon:
	$(GO_BUILD) -o bin/$@ ./tools/protoc-gen-go-tetragon/

# renovate: datasource=docker
GOLANGCILINT_IMAGE=docker.io/golangci/golangci-lint:v1.57.2@sha256:8f3a60a00a83bb7d599d2e028ac0c3573dc2b9ec0842590f1c2e59781c821da7
GOLANGCILINT_WANT_VERSION := $(subst @sha256,,$(patsubst v%,%,$(word 2,$(subst :, ,$(lastword $(subst /, ,$(GOLANGCILINT_IMAGE)))))))
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)
.PHONY: check
ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
check:
	golangci-lint run
else
check:
	$(CONTAINER_ENGINE) run --rm -v `pwd`:/app:Z -w /app --env GOTOOLCHAIN=auto $(GOLANGCILINT_IMAGE) golangci-lint run
endif

.PHONY: copy-golangci-lint
copy-golangci-lint:
	mkdir -p bin/
	$(eval xid=$(shell $(CONTAINER_ENGINE) create $(GOLANGCILINT_IMAGE)))
	echo ${xid}
	docker cp ${xid}:/usr/bin/golangci-lint bin/golangci-lint
	docker rm ${xid}

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
	find . -name '*.go' -not -path '**/vendor/*' -not -path './pkg/k8s/vendor/*' -not -path './api/v1/tetragon/*' | xargs goimports -w

.PHONY: format
format: go-format clang-format

# generate cscope for bpf files
cscope:
	find bpf -name "*.[chxsS]" -print > cscope.files
	cscope -b -q -k
.PHONY: cscope

tester-progs:
	$(MAKE) -C $(TESTER_PROGS_DIR)
.PHONY: tester-progs

.PHONY: version
version:
	@echo $(VERSION)

.PHONY: docs
docs:
	$(MAKE) -C docs

.PHONY: kind
kind:
	./contrib/localdev/bootstrap-kind-cluster.sh

.PHONY: kind-install-tetragon
kind-install-tetragon:
	./contrib/localdev/install-tetragon.sh --image cilium/tetragon:latest --operator cilium/tetragon-operator:latest

.PHONY: kind-setup
kind-setup: images kind kind-install-tetragon

METRICS_DOCS_PATH := docs/content/en/docs/reference/metrics.md

.PHONY: metrics-docs
metrics-docs: tetra
	echo '---' > $(METRICS_DOCS_PATH)
	echo 'title: "Metrics"' >> $(METRICS_DOCS_PATH)
	echo 'description: >' >> $(METRICS_DOCS_PATH)
	echo '  This reference is autogenerated from the Tetragon Prometheus metrics registry.' >> $(METRICS_DOCS_PATH)
	echo 'weight: 4' >> $(METRICS_DOCS_PATH)
	echo '---' >> $(METRICS_DOCS_PATH)
	echo '{{< comment >}}' >> $(METRICS_DOCS_PATH)
	echo 'This page is autogenerated via `make metrics-doc` please do not edit directly.' >> $(METRICS_DOCS_PATH)
	echo '{{< /comment >}}' >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetra metrics-docs health >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetra metrics-docs resources >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetra metrics-docs events >> $(METRICS_DOCS_PATH)

.PHONY: lint-metrics-md
lint-metrics-md: metrics-docs
	@if [ -n "$$(git status --porcelain $(METRICS_DOCS_PATH))" ]; then \
		echo "metrics doc out of sync; please run 'make metrics-docs'" > /dev/stderr; \
		false; \
	fi
