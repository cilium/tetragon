# Copyright Authors of Tetragon
# SPDX-License-Identifier: Apache-2.0

include Makefile.defs

INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
DOCKER_IMAGE_TAG ?= latest
LOCAL_CLANG ?= 0
LOCAL_CLANG_FORMAT ?= 0
FORMAT_FIND_FLAGS ?= -name '*.c' -o -name '*.h'
NOOPT ?= 0
CLANG_IMAGE = quay.io/cilium/clang:b97f5b3d5c38da62fb009f21a53cd42aefd54a2f@sha256:e1c8ed0acd2e24ed05377f2861d8174af28e09bef3bbc79649c8eba165207df0
TESTER_PROGS_DIR = "contrib/tester-progs"
# Extra flags to pass to test binary
EXTRA_TESTFLAGS ?=
SUDO ?= sudo
GO_TEST_TIMEOUT ?= 20m
E2E_TEST_TIMEOUT ?= 20m
BUILD_PKG_DIR ?= $(shell pwd)/build/$(TARGET_ARCH)
VERSION ?= $(shell git describe --tags --always --exclude '*/*')
CONTAINER_ENGINE_ARGS ?=

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
GO_BUILD_HOOK = CGO_ENABLED=0 GOARCH=$(GOARCH) $(GO) -C contrib/tetragon-rthooks build $(GO_BUILD_FLAGS)

.PHONY: all
all: tetragon-bpf tetragon tetra test-compile tester-progs protoc-gen-go-tetragon tetragon-bench

-include Makefile.cli

.PHONY: clean
clean: cli-clean tarball-clean
	$(MAKE) -C ./bpf clean
	rm -f go-tests/*.test ./ksyms ./tetragon ./tetragon-operator ./tetra ./alignchecker ./tetragon.exe
	rm -f contrib/sigkill-tester/sigkill-tester contrib/namespace-tester/test_ns contrib/capabilities-tester/test_caps
	$(MAKE) -C $(TESTER_PROGS_DIR) clean

##@ Build and install

.PHONY: tetragon
tetragon: ## Compile the Tetragon agent.
	$(GO_BUILD) ./cmd/tetragon/

.PHONY: tetragon-operator
tetragon-operator: ## Compile the Tetragon operator.
	$(GO_BUILD) -o $@ ./operator

.PHONY: tetra
tetra: ## Compile the Tetragon gRPC client.
	$(GO_BUILD) ./cmd/tetra/

.PHONY: tetragon-bpf
ifeq (1,$(LOCAL_CLANG))
tetragon-bpf: tetragon-bpf-local ## Compile bpf programs (use LOCAL_CLANG=0 to compile in a Docker build env).
else
tetragon-bpf: tetragon-bpf-container
endif

.PHONY: tetragon-bpf-local
tetragon-bpf-local:
	$(MAKE) -C ./bpf BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) -j$(JOBS) $(__BPF_DEBUG_FLAGS)

.PHONY: tetragon-bpf-container
tetragon-bpf-container:
	$(CONTAINER_ENGINE) rm -f tetragon-clang || true
	$(CONTAINER_ENGINE) run -v $(CURDIR):/tetragon:Z -u $$(id -u) -e BPF_TARGET_ARCH=$(BPF_TARGET_ARCH) --name tetragon-clang $(CLANG_IMAGE) make -C /tetragon/bpf -j$(JOBS) $(__BPF_DEBUG_FLAGS)
	$(CONTAINER_ENGINE) rm -f tetragon-clang

.PHONY: tetragon-bench
tetragon-bench: ## Compile tetragon-bench tool.
	$(GO_BUILD) ./cmd/tetragon-bench/

.PHONY: tetragon-oci-hook
tetragon-oci-hook:
	$(GO_BUILD_HOOK) -o $@ ./cmd/oci-hook

.PHONY: tetragon-nri-hook
tetragon-nri-hook:
	$(GO_BUILD_HOOK) -o $@ ./cmd/nri-hook

.PHONY: tetragon-oci-hook-setup
tetragon-oci-hook-setup:
	$(GO_BUILD_HOOK) -o $@ ./cmd/setup

.PHONY: ksyms
ksyms:
	$(GO) build ./cmd/ksyms/

.PHONY: compile-commands
compile-commands: ## Generate a compile_commands.json with bear for bpf programs.
	$(MAKE) -C ./bpf clean
	bear -- $(MAKE) -C ./

.PHONY: install
install: ## Install tetragon agent and tetra as standalone binaries.
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./tetragon $(DESTDIR)$(BINDIR)

##@ Container images

.PHONY: image
image: ## Build the Tetragon agent container image.
	$(CONTAINER_ENGINE) build -t "cilium/tetragon:${DOCKER_IMAGE_TAG}" --target release --build-arg TETRAGON_VERSION=$(VERSION) ${CONTAINER_ENGINE_ARGS} --platform=linux/${TARGET_ARCH} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push cilium/tetragon:$(DOCKER_IMAGE_TAG)"

.PHONY: image-operator
image-operator: ## Build the Tetragon operator container image.
	$(CONTAINER_ENGINE) build -f Dockerfile.operator -t "cilium/tetragon-operator:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push cilium/tetragon-operator:$(DOCKER_IMAGE_TAG)"

.PHONY: image-rthooks
image-rthooks:
	$(CONTAINER_ENGINE) build -f Dockerfile.rthooks -t "cilium/tetragon-rthooks:${DOCKER_IMAGE_TAG}" --platform=linux/${TARGET_ARCH} .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push cilium/tetragon-rthooks:$(DOCKER_IMAGE_TAG)"

.PHONY: image-test
image-test: image-clang
	$(CONTAINER_ENGINE) build -f Dockerfile.test -t "cilium/tetragon-test:${DOCKER_IMAGE_TAG}" .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push cilium/tetragon-test:$(DOCKER_IMAGE_TAG)"

.PHONY: image-clang
image-clang:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang --build-arg VERSION=1:15.0.7-0ubuntu0.22.04.2 -t "cilium/clang:${DOCKER_IMAGE_TAG}" .
	@echo "Push like this when ready:"
	@echo "${CONTAINER_ENGINE} push cilium/clang:$(DOCKER_IMAGE_TAG)"

.PHONY: images
images: image image-operator ## Convenience alias for image and image-operator.

##@ Packages

.PHONY: tarball
# Share same build environment as docker image
# Then it uses docker save to dump the layer and use it to
# contruct the tarball.
# Requires 'jq' to be installed
tarball: tarball-clean image ## Build Tetragon compressed tarball.
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

.PHONY: tarball-release
tarball-release: tarball ## Build Tetragon release tarball.
	mkdir -p release/
	mv $(BUILD_PKG_DIR)/linux-tarball/tetragon-$(VERSION)-$(TARGET_ARCH).tar.gz release/
	(cd release && sha256sum tetragon-$(VERSION)-$(TARGET_ARCH).tar.gz > tetragon-$(VERSION)-$(TARGET_ARCH).tar.gz.sha256sum)

.PHONY: tarball-clean
tarball-clean:
	rm -fr $(BUILD_PKG_DIR)

##@ Test

# renovate: datasource=docker
GOLANGCILINT_IMAGE=docker.io/golangci/golangci-lint:v2.7.1@sha256:d5162141f0d4489657eade74cf082e4038a41a9bcfe645c2a5f991df308e20d8
GOLANGCILINT_WANT_VERSION := $(subst @sha256,,$(patsubst v%,%,$(word 2,$(subst :, ,$(lastword $(subst /, ,$(GOLANGCILINT_IMAGE)))))))
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)
.PHONY: check
ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
check: ## Run Go linters.
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

.PHONY: test
test: tester-progs tetragon-bpf ## Run Go tests.
	$(GO) test -exec "$(SUDO)" -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(GO_TEST_TIMEOUT) -failfast -cover ./pkg/... ./cmd/... ./operator/... ${EXTRA_TESTFLAGS}

.PHONY: tester-progs
tester-progs: ## Compile helper programs for unit testing.
	$(MAKE) -C $(TESTER_PROGS_DIR)

## bpf-test: ## run BPF tests.
## bpf-test BPFGOTESTFLAGS="-v": ## run BPF tests with verbose.
.PHONY: bpf-test
bpf-test:
	$(MAKE) -C ./bpf run-test

.PHONY: verify
verify: tetragon-bpf ## Verify BPF programs.
	sudo DEBUG=${DEBUG} TETRAGONDIR=$(CURDIR)/bpf/objs $(GO) test contrib/verify/verify_test.go -v

.PHONY: alignchecker
alignchecker: ## Run alignchecker.
	$(GO) test -c ./pkg/alignchecker -o alignchecker

.PHONY: bench
bench: ## Run Go benchmarks.
	$(GO) test -exec "$(SUDO)" -p 1 -parallel 1 -run ^$$ $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(GO_TEST_TIMEOUT) -failfast -cover ./pkg/... ./cmd/... ./operator/... -bench=. ${EXTRA_TESTFLAGS}

TEST_COMPILE ?= ./...
.PHONY: test-compile
test-compile: ## Compile unit tests.
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

.PHONY: fetch-testdata
fetch-testdata:
	wget -nc -P testdata/btf 'https://github.com/cilium/tetragon-testdata/raw/main/btf/vmlinux-5.4.104+'

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

# List e2e-test packages that can run in parallel
.PHONY: ls-e2e-test
ls-e2e-test:
	@$(GO) list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' $(E2E_TESTS)

## e2e-test: ## run e2e tests
## e2e-test E2E_BUILD_IMAGES=0: ## run e2e tests without (re-)building images
## e2e-test E2E_TESTS=./tests/e2e/tests/skeleton: ## run a specific e2e test
.PHONY: e2e-test
ifneq ($(E2E_BUILD_IMAGES), 0)
e2e-test: image image-operator
else
e2e-test:
endif
	$(GO) list $(E2E_TESTS) | xargs -Ipkg $(GO) test $(GOFLAGS) -gcflags=$(GO_BUILD_GCFLAGS) -timeout $(E2E_TEST_TIMEOUT) -failfast -cover pkg ${EXTRA_TESTFLAGS} -fail-fast -tetragon.helm.set tetragon.image.override="$(E2E_AGENT)" -tetragon.helm.set tetragonOperator.image.override="$(E2E_OPERATOR)" -tetragon.helm.url="" -tetragon.helm.chart="$(realpath ./install/kubernetes/tetragon)" $(E2E_BTF_FLAGS)

##@ Development

.PHONY: cscope
cscope: ## Generate cscope for bpf files.
	find bpf -name "*.[chxsS]" -print > cscope.files
	cscope -b -q -k

.PHONY: gen-compile-commands
BEAR_CLI := $(shell which bear 2> /dev/null)
gen-compile-commands: ## Generates compile_commands.json
ifeq ($(BEAR_CLI),)
	@echo "Error: 'bear' must be installed and available in \$\$PATH to generate the compile_commands.json"
	@exit 1
else
	@echo "Generating compile_commands.json using bear..."
	@$(BEAR_CLI) $(MAKE) tetragon-bpf LOCAL_CLANG=1 LOCAL_CLANG_FORMAT=1
endif


.PHONY: kind
kind: ## Create a kind cluster for Tetragon development.
	./contrib/kind/bootstrap-kind-cluster.sh

KIND_BUILD_IMAGES ?= 1
VALUES ?=

## kind-install-tetragon: ## Install Tetragon in a kind cluster.
## kind-install-tetragon KIND_BUILD_IMAGES=0: ## Install Tetragon in a kind cluster without (re-)building images.
## kind-install-tetragon VALUES=values.yaml: ## Install Tetragon in a kind cluster using additional Helm values.
.PHONY: kind-install-tetragon
ifneq ($(KIND_BUILD_IMAGES), 0)
kind-install-tetragon: images
else
kind-install-tetragon:
endif
ifneq ($(VALUES),)
	./contrib/kind/install-tetragon.sh -v $(VALUES)
else
	./contrib/kind/install-tetragon.sh
endif

.PHONY: kind-setup
kind-setup: kind kind-install-tetragon ## Create a kind cluster and install local version of Tetragon.

.PHONY: kind-down
kind-down: ## Delete a kind cluster for Tetragon development.
	./contrib/kind/delete-kind-cluster.sh

##@ Chores and generated files

.PHONY: codegen protogen
codegen: | protogen
protogen: protoc-gen-go-tetragon ## Generate code based on .proto files.
	# Need to call vendor twice here, once before and once after codegen the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) -C api vendor
	$(MAKE) -C api
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
	$(MAKE) -C contrib/tetragon-rthooks vendor

.PHONY: protoc-gen-go-tetragon
protoc-gen-go-tetragon:
	$(GO_BUILD) -o bin/$@ ./tools/protoc-gen-go-tetragon/

.PHONY: generate crds
generate: | crds
crds: ## Generate kubebuilder files.
	# Need to call vendor twice here, once before and once after generate, the reason
	# being we need to grab changes first plus pull in whatever gets generated here.
	$(MAKE) -C pkg/k8s vendor
	$(MAKE) -C pkg/k8s
	$(MAKE) -C pkg/k8s vendor
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
	# YAML CRDs also live in the helm charts, so update them as well.
	$(MAKE) -C install/kubernetes tetragon/crds-yaml

.PHONY: vendor
vendor: ## Tidy and vendor Go modules.
	$(MAKE) -C api vendor
	$(MAKE) -C pkg/k8s vendor
	$(MAKE) -C contrib/tetragon-rthooks vendor
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

.PHONY: clang-format
ifeq (1,$(LOCAL_CLANG_FORMAT))
clang-format: ## Run code formatter on BPF code.
	find bpf $(FORMAT_FIND_FLAGS) | xargs -n 1000 clang-format -i -style=file
else
clang-format:
	$(CONTAINER_ENGINE) build -f Dockerfile.clang-format -t "cilium/clang-format:${DOCKER_IMAGE_TAG}" .
	find bpf $(FORMAT_FIND_FLAGS) | xargs -n 1000 \
		$(CONTAINER_ENGINE) run -v $(shell realpath .):/tetragon "cilium/clang-format:${DOCKER_IMAGE_TAG}" -i -style=file
endif

.PHONY: go-format
go-format: ## Run code formatter on Go code.
	find . -name '*.go' -not -path '**/vendor/*' -not -path './pkg/k8s/vendor/*' -not -path './api/v1/tetragon/*' -not -path './pkg/k8s/apis/cilium.io/v1alpha1/zz_generated.deepcopy.go' | \
	  xargs goimports -local github.com/cilium/tetragon,github.com/cilium/tetragon/api,github.com/cilium/tetragon/pkg/k8s -w

.PHONY: format
format: go-format clang-format ## Convenience alias for clang-format and go-format.

.PHONY: validate
validate: check format generate-flags metrics-docs ## Convenience target running linters, formatters and generators across the codebase.
	# FIXME: add api linting once we fix the lints
	$(MAKE) -C api vendor format proto
	$(MAKE) -C pkg/k8s vendor generate
	# Vendoring includes api and pkg/k8s vendoring. To avoid running vendor
	# million times, run the global vendor target after api and pkg/k8s builds.
	$(MAKE) vendor
	$(MAKE) -C install/kubernetes
	$(MAKE) -C install/kubernetes validation

.PHONY: checkpatch
# renovate: datasource=docker
CHECKPATCH_IMAGE := quay.io/cilium/cilium-checkpatch:1755701578-b97bd7a@sha256:f1332fa6edbbd40882a59ceae4a7843a4095bd62288363740e84b82708624c50
CHECKPATCH_IGNORE := --ignore PREFER_DEFINED_ATTRIBUTE_MACRO,C99_COMMENTS,OPEN_ENDED_LINE,PREFER_KERNEL_TYPES,REPEATED_WORD,SPDX_LICENSE_TAG,LONG_LINE,LONG_LINE_STRING,LONG_LINE_COMMENT,TRACE_PRINTK,AVOID_EXTERNS,ENOSYS,MACRO_ARG_REUSE
ifneq ($(CHECKPATCH_DEBUG),)
  # Run script with "bash -x"
  CHECKPATCH_IMAGE_AND_ENTRY := \
	--entrypoint /bin/bash $(CHECKPATCH_IMAGE) -x /checkpatch/checkpatch.sh -- $(CHECKPATCH_IGNORE)
else
  # Use default entrypoint
  CHECKPATCH_IMAGE_AND_ENTRY := \
	--entrypoint /bin/bash $(CHECKPATCH_IMAGE) /checkpatch/checkpatch.sh -- $(CHECKPATCH_IGNORE)
endif
checkpatch: ## Run checkpatch on your current branch commits.
	$(QUIET) $(CONTAINER_ENGINE) container run --rm \
		--workdir /workspace \
		--volume $(CURDIR):/workspace \
		--user "$(shell id -u):$(shell id -g)" \
		-e GITHUB_REF=$(GITHUB_REF) -e GITHUB_REPOSITORY=$(GITHUB_REPOSITORY) -e GITHUB_TOKEN=$(GITHUB_TOKEN) \
		$(CHECKPATCH_IMAGE_AND_ENTRY) $(CHECKPATCH_ARGS)

##@ Documentation

.PHONY: docs
docs: ## Build and preview documentation website.
	$(MAKE) -C docs

.PHONY: gen-docs-references
gen-docs-references: generate-flags metrics-docs tracing-policy-docs ## Convenience alias to generate all docs references.

.PHONY: tracing-policy-docs
tracing-policy-docs: ## Generate TracingPolicy reference for documentation.
	$(MAKE) -C docs tracing-policy-docs

.PHONY: generate-flags
generate-flags: tetragon ## Generate daemon flags reference for documentation.
	echo "$$(./tetragon --generate-docs)" > docs/data/tetragon_flags.yaml

METRICS_DOCS_PATH := docs/content/en/docs/reference/metrics.md

.PHONY: tetragon-metrics-docs
tetragon-metrics-docs:
	$(GO_BUILD) ./cmd/tetragon-metrics-docs/

.PHONY: metrics-docs ## Generate metrics reference for documentation.
metrics-docs: tetragon-metrics-docs ## Generate metrics reference documentation page.
	echo '---' > $(METRICS_DOCS_PATH)
	echo 'title: "Metrics"' >> $(METRICS_DOCS_PATH)
	echo 'description: >' >> $(METRICS_DOCS_PATH)
	echo '  This reference is autogenerated from the Tetragon Prometheus metrics registry.' >> $(METRICS_DOCS_PATH)
	echo 'weight: 4' >> $(METRICS_DOCS_PATH)
	echo '---' >> $(METRICS_DOCS_PATH)
	echo '{{< comment >}}' >> $(METRICS_DOCS_PATH)
	echo 'This page is autogenerated via `make metrics-doc` please do not edit directly.' >> $(METRICS_DOCS_PATH)
	echo '{{< /comment >}}' >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs health >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs resources >> $(METRICS_DOCS_PATH)
	$(CONTAINER_ENGINE) run --rm -v $(PWD):$(PWD) -w $(PWD) $(GO_IMAGE) ./tetragon-metrics-docs events >> $(METRICS_DOCS_PATH)


##@ Others

.PHONY: help
help: ## Display this help, based on https://www.thapaliya.com/en/writings/well-documented-makefiles/
	$(call print_help_from_comments)
	@printf "\n\033[1m%s\033[0m\n" Options
	$(call print_help_option,TARGET_ARCH,target architecture to build for (e.g. amd64 or arm64))
	$(call print_help_option,BPF_TARGET_ARCH,target architecture for BPF progs (set by TARGET_ARCH))
	$(call print_help_option,GO_ARCH,target architecture for Go progs (set by TARGET_ARCH))
	$(call print_help_option,DEBUG,enable NOOPT and NOSTRIP)
	$(call print_help_option,NOOPT,disable optimization in Go build (set by DEBUG))
	$(call print_help_option,NOSTRIP,disable binary stripping in Go build (set by DEBUG))
	$(call print_help_option,LOCAL_CLANG,use the local clang install for BPF compilation)
	$(call print_help_option,JOBS,number of jobs to run for BPF compilation (default to nproc))
	$(call print_help_option,EXTRA_GO_BUILD_LDFLAGS,extra flags to pass to the Go linker)
	$(call print_help_option,EXTRA_GO_BUILD_FLAGS,extra flags to pass to the Go builder)
	$(call print_help_option,EXTRA_TESTFLAGS,extra flags to pass to the test binary)

.PHONY: version chart-version
version: ## Print Tetragon version.
	@echo $(VERSION)

chart-version: ## Print Tetragon OCI Helm chart version.
	@echo $(VERSION) | sed 's/^v\(.*\)/\1/'

