# This Dockerfile can be used to compile natively on amd64 and cross-compile on
# amd64 for arm64.
#
# It can technically build natively on arm64 and cross-compile on arm64 for
# amd64 but the steps involving the gcc cross compiler might need rework. It's
# assumed that if [ $BUILDARCH != $TARGETARCH ] we are cross-compiling from
# amd64 to arm64
#
# For help on Docker cross compilation see the following blogpost:
# https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/

# First builder (cross-)compile the BPF programs
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang:b97f5b3d5c38da62fb009f21a53cd42aefd54a2f@sha256:e1c8ed0acd2e24ed05377f2861d8174af28e09bef3bbc79649c8eba165207df0 AS bpf-builder
WORKDIR /go/src/github.com/cilium/tetragon
RUN apt-get update && apt-get install -y --no-install-recommends linux-libc-dev gzip && rm -rf /var/lib/apt/lists/*
COPY bpf/ ./bpf/
ARG TARGETARCH
ARG COMPRESS_BPF
RUN case "${TARGETARCH}" in \
        amd64) BPF_TARGET_ARCH=x86 ;; \
        arm64) BPF_TARGET_ARCH=arm64 ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    make -C ./bpf BPF_TARGET_ARCH=${BPF_TARGET_ARCH} -j"$(nproc)"
RUN if [ "$COMPRESS_BPF" = "gzip" ]; then gzip bpf/objs/*.o; fi

# Second builder (cross-)compile tetragon and tetra
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.0@sha256:c83e68f3ebb6943a2904fa66348867d108119890a2c6a2e6f07b38d0eb6c25c5 AS tetragon-builder
WORKDIR /go/src/github.com/cilium/tetragon
ARG TETRAGON_VERSION TARGETARCH
COPY Makefile Makefile.defs go.mod go.sum ./
COPY api/ ./api/
COPY cmd/ ./cmd/
COPY pkg/ ./pkg/
COPY tests/policytests/ ./tests/policytests/
COPY vendor/ ./vendor/
RUN make VERSION=$TETRAGON_VERSION TARGET_ARCH=$TARGETARCH tetragon tetra

# Third builder (cross-)compile a stripped gops
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS gops
ARG TARGETARCH
# renovate: datasource=github-releases depName=google/gops
RUN GOARCH=$TARGETARCH CGO_ENABLED=0 go install -ldflags="-s -w" github.com/google/gops@v0.3.29 && \
    gops_bin="$(go env GOPATH)/bin/gops" && \
    if [ ! -f "$gops_bin" ]; then gops_bin="$(go env GOPATH)/bin/linux_${TARGETARCH}/gops"; fi && \
    if [ "$gops_bin" != "/go/bin/gops" ]; then cp "$gops_bin" /go/bin/gops; fi

# This builder (cross-)compile a stripped static version of bpftool.
# This step was kept because the downloaded version includes LLVM libs with the
# disassembler that makes the static binary grow from ~2Mo to ~30Mo.
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang:b97f5b3d5c38da62fb009f21a53cd42aefd54a2f@sha256:e1c8ed0acd2e24ed05377f2861d8174af28e09bef3bbc79649c8eba165207df0 AS bpftool-builder
WORKDIR /bpftool
ARG TARGETARCH BUILDARCH
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get update && echo "Types: deb\n\
URIs: http://archive.ubuntu.com/ubuntu/\n\
Suites: noble noble-updates noble-backports\n\
Components: main universe restricted multiverse\n\
Architectures: amd64\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\
\n\
Types: deb\n\
URIs: http://archive.ubuntu.com/ubuntu/\n\
Suites: noble-security\n\
Components: main universe restricted multiverse\n\
Architectures: amd64\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\
\n\
Types: deb\n\
URIs: http://ports.ubuntu.com/\n\
Suites: noble noble-updates noble-backports noble-security\n\
Components: main universe restricted multiverse\n\
Architectures: arm64\n\
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" > /etc/apt/sources.list.d/ubuntu.sources \
    && dpkg --add-architecture arm64; fi
RUN apt-get update
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libelf-dev:arm64 libcap-dev:arm64 crossbuild-essential-$TARGETARCH; \
    else apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libcap-dev; fi
# v7.3.0
ENV BPFTOOL_REV="687e7f06f2ee104ed6515ec3a9816af77bfa7a17"
RUN git clone https://github.com/libbpf/bpftool.git . && git checkout ${BPFTOOL_REV} && git submodule update --init --recursive
# From Ubuntu 24.04 builder image, libzstd must be added at the end of LIBS and LIBS_BOOTSTRAP to compile statically
RUN sed -i 's/\(LIBS = $(LIBBPF) -lelf -lz\)/\1 -lzstd/; s/\(LIBS_BOOTSTRAP = $(LIBBPF_BOOTSTRAP) -lelf -lz\)/\1 -lzstd/' src/Makefile
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then make -C src EXTRA_CFLAGS=--static CC=aarch64-linux-gnu-gcc -j $(nproc) && aarch64-linux-gnu-strip src/bpftool; \
    else make -C src EXTRA_CFLAGS=--static -j $(nproc) && strip src/bpftool; fi

# This stage downloads a stripped static version of bpftool with LLVM disassembler
FROM --platform=$BUILDPLATFORM quay.io/cilium/alpine-curl@sha256:408430f548a8390089b9b83020148b0ef80b0be1beb41a98a8bfe036709c196e AS bpftool-downloader
ARG TARGETARCH
ARG BPFTOOL_TAG=v7.2.0-snapshot.0
RUN curl -L https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_TAG}/bpftool-${BPFTOOL_TAG}-${TARGETARCH}.tar.gz | tar xz && chmod +x bpftool

# Almost final step runs on target platform (might need emulation) and
# retrieves (cross-)compiled binaries from builders
FROM docker.io/library/alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659 AS base-build
RUN apk add --no-cache iproute2 && \
    mkdir /var/lib/tetragon/ && \
    mkdir -p /etc/tetragon/tetragon.conf.d/ && \
    mkdir -p /etc/tetragon/tetragon.tp.d/
COPY --from=tetragon-builder /go/src/github.com/cilium/tetragon/tetragon /usr/bin/
COPY --from=tetragon-builder /go/src/github.com/cilium/tetragon/tetra /usr/bin/
COPY --from=gops /go/bin/gops /usr/bin/
COPY --from=bpf-builder /go/src/github.com/cilium/tetragon/bpf/objs/* /var/lib/tetragon/
ENTRYPOINT ["/usr/bin/tetragon"]

# This target only builds with the `--target release` option and reduces the
# size of the final image with a static build of bpftool without the LLVM
# disassembler
FROM base-build AS release
COPY --from=bpftool-builder bpftool/src/bpftool /usr/bin/bpftool

FROM base-build
COPY --from=bpftool-downloader /bpftool /usr/bin/bpftool
