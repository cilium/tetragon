GO ?= go
export TARGET_ARCH ?= amd64
INSTALL = $(QUIET)install
BINDIR ?= /usr/local/bin
CONTAINER_ENGINE ?= docker
DOCKER_IMAGE_TAG ?= latest
LOCAL_CLANG ?= 0
LOCAL_CLANG_FORMAT ?= 0
FORMAT_FIND_FLAGS ?= -name '*.c' -o -name '*.h' -not -path 'bpf/include/vmlinux.h' -not -path 'bpf/include/api.h' -not -path 'bpf/libbpf/*'
NOOPT ?= 0
CLANG_IMAGE = quay.io/cilium/clang@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f
TESTER_PROGS_DIR = "contrib/tester-progs"
# Extra flags to pass to test binary
EXTRA_TESTFLAGS ?=
SUDO ?= sudo

BUILD_PKG_DIR ?= $(shell pwd)/build/$(TARGET_ARCH)

VERSION ?= $(shell git describe --tags --always)
GO_GCFLAGS ?= ""
GO_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)'"
GO_LDFLAGS_STATIC="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)' -linkmode=external -extldflags=-static"
GO_IMAGE_LDFLAGS=$(GO_LDFLAGS_STATIC)
GO_OPERATOR_IMAGE_LDFLAGS="-X 'github.com/cilium/tetragon/pkg/version.Version=$(VERSION)' -s -w"


GOLANGCILINT_WANT_VERSION = 1.50.1
GOLANGCILINT_VERSION = $(shell golangci-lint version 2>/dev/null)


.PHONY: all
all: tetragon-bpf tetragon tetra tetragon-alignchecker test-compile tester-progs protoc-gen-go-tetragon tetragon-bench

-include Makefile.docker
-include Makefile.cli

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
	@echo '    compile-commands  - generate a compile_commands.json with bear for bpf programs'
	@echo '    cli-release       - compile tetra CLI release binaries'
	@echo 'Container images:'
	@echo '    image             - build the Tetragon agent container image'
	@echo '    image-operator    - build the Tetragon operator container image'
	@echo 'Packages:'
	@echo '    tarball           - build Tetragon compressed tarball'
	@echo '    tarball-release   - build Tetragon release tarball'
	@echo 'Generated files:'
	@echo '    codegen           - generate code based on .proto files'
	@echo '    generate          - generate kubebuilder files'
	@echo 'Linting and chores:'
	@echo '    vendor            - tidy and vendor Go modules'
	@echo '    clang-format      - run code formatter on BPF code'
	@echo '    go-format         - run code formatter on Go code'
	@echo '    format            - convenience alias for clang-format and go-format'

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

ifeq (1,$(NOOPT))
GO_GCFLAGS = "all=-N -l"
endif

ifeq (1,$(STATIC))
GO_LDFLAGS = $(GO_LDFLAGS_STATIC)
endif

tetragon-bpf-local:
	$(MAKE) -C ./bpf

tetragon-bpf-container:
	$(CONTAINER_ENGINE) rm tetragon-clang || true
	$(CONTAINER_ENGINE) run -v $(CURDIR):/tetragon:Z -u $$(id -u) -e TARGET_ARCH=$(TARGET_ARCH) --name tetragon-clang $(CLANG_IMAGE) $(MAKE) -C /tetragon/bpf
	$(CONTAINER_ENGINE) rm tetragon-clang

.PHONY: verify
verify: tetragon-bpf
	sudo contrib/verify/verify.sh bpf/objs

.PHONY: tetragon tetra tetragon-operator tetragon-alignchecker tetragon-bench
tetragon:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor ./cmd/tetragon/

tetra:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor ./cmd/tetra/

tetragon-bench:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor ./cmd/tetragon-bench/

tetragon-operator:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor -o $@ ./operator

tetragon-alignchecker:
	$(GO) build -gcflags=$(GO_GCFLAGS) -ldflags=$(GO_LDFLAGS) -mod=vendor -o $@ ./tools/alignchecker/

.PHONY: ksyms
ksyms:
	$(GO) build ./cmd/ksyms/

.PHONY: tetragon-image tetragon-operator-image
tetragon-image:
	GOOS=linux GOARCH=amd64 $(GO) build -tags netgo -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/tetragon/
	GOOS=linux GOARCH=amd64 $(GO) build -tags netgo -mod=vendor -ldflags=$(GO_IMAGE_LDFLAGS) ./cmd/tetra/

tetragon-operator-image:
	CGO_ENABLED=0 $(GO) build -ldflags=$(GO_OPERATOR_IMAGE_LDFLAGS) -mod=vendor -o tetragon-operator ./operator

.PHONY: install
install:
	groupadd -f hubble
	$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 ./tetragon $(DESTDIR)$(BINDIR)

.PHONY: vendor
vendor:
	$(MAKE) -C ./api vendor
	$(MAKE) -C ./pkg/k8s vendor
	$(GO) mod tidy -compat=1.18
	$(GO) mod vendor
	$(GO) mod verify

.PHONY: clean
clean: cli-clean tarball-clean
	$(MAKE) -C ./bpf clean
	rm -f go-tests/*.test ./ksyms ./tetragon ./tetragon-operator ./tetra ./tetragon-alignchecker
	rm -f contrib/sigkill-tester/sigkill-tester contrib/namespace-tester/test_ns contrib/capabilities-tester/test_caps
	$(MAKE) -C $(TESTER_PROGS_DIR) clean

.PHONY: test
test: tester-progs tetragon-bpf
	$(SUDO) $(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_GCFLAGS) -timeout 20m -failfast -cover ./pkg/... ./cmd/... ${EXTRA_TESTFLAGS}

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

# Run an e2e-test
.PHONY: e2e-test
ifneq ($(E2E_BUILD_IMAGES), 0)
e2e-test: image image-operator
else
e2e-test:
endif
	$(GO) test -p 1 -parallel 1 $(GOFLAGS) -gcflags=$(GO_GCFLAGS) -timeout 20m -failfast -cover ./tests/e2e/tests/... ${EXTRA_TESTFLAGS} -fail-fast -tetragon.helm.set tetragon.image.override="$(E2E_AGENT)" -tetragon.helm.set tetragonOperator.image.override="$(E2E_OPERATOR)" -tetragon.helm.url="" -tetragon.helm.chart="$(realpath ./install/kubernetes)" $(E2E_BTF_FLAGS)

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

.PHONY: lint
lint:
	golint -set_exit_status $$(go list ./...)

.PHONY: image image-operator image-test image-codegen
image:
	$(CONTAINER_ENGINE) build -t "cilium/tetragon:${DOCKER_IMAGE_TAG}" --build-arg TETRAGON_VERSION=$(VERSION) .
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
	$(CONTAINER_ENGINE) build -f Dockerfile.clang --build-arg VERSION=1:14.0.0-1ubuntu1 -t "cilium/clang:${DOCKER_IMAGE_TAG}" .
	$(QUIET)echo "Push like this when ready:"
	$(QUIET)echo "${CONTAINER_ENGINE} push cilium/clang:$(DOCKER_IMAGE_TAG)"

image-clang-arm:
	# to compile bpf programs for arm, put 'docker.io/cilium/clang.arm:latest' to CLANG_IMAGE
	$(CONTAINER_ENGINE) build -f Dockerfile.clang.arm -t "cilium/clang.arm:${DOCKER_IMAGE_TAG}" .

.PHONY: tarball tarball-release tarball-clean
# Share same build environment as docker image
tarball: tarball-clean image
	$(CONTAINER_ENGINE) build --build-arg TETRAGON_VERSION=$(VERSION) --build-arg TARGET_ARCH=$(TARGET_ARCH) -f Dockerfile.tarball -t "cilium/tetragon-tarball:${DOCKER_IMAGE_TAG}" .
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)
	$(CONTAINER_ENGINE) save cilium/tetragon-tarball:$(DOCKER_IMAGE_TAG) -o $(BUILD_PKG_DIR)/tetragon-$(VERSION)-$(TARGET_ARCH).tmp.tar
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)/docker/
	$(QUIET)mkdir -p $(BUILD_PKG_DIR)/linux-tarball/
	tar xC $(BUILD_PKG_DIR)/docker/ -f $(BUILD_PKG_DIR)/tetragon-$(VERSION)-$(TARGET_ARCH).tmp.tar
	find $(BUILD_PKG_DIR)/docker/ -name 'layer.tar' -exec cp '{}' $(BUILD_PKG_DIR)/linux-tarball/tetragon-$(VERSION)-$(TARGET_ARCH).tar \;
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

.PHONY: generate codegen protoc-gen-go-tetragon
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

.PHONY: check
ifneq (,$(findstring $(GOLANGCILINT_WANT_VERSION),$(GOLANGCILINT_VERSION)))
check:
	golangci-lint run
else
check:
	$(CONTAINER_ENGINE) build -t golangci-lint:tetragon . -f Dockerfile.golangci-lint
	$(CONTAINER_ENGINE) run --rm -v `pwd`:/app:Z -w /app golangci-lint:tetragon golangci-lint run
endif

.PHONY: copy-golangci-lint
copy-golangci-lint:
	mkdir -p bin/
	$(CONTAINER_ENGINE) build -t golangci-lint:tetragon . -f Dockerfile.golangci-lint
	$(eval xid=$(shell docker create golangci-lint:tetragon))
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
	find . -name '*.go' -not -path './vendor/*' -not -path './api/vendor/*' -not -path './pkg/k8s/vendor/*' -not -path './api/v1/tetragon/codegen/*' | xargs gofmt -w

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
