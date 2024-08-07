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
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang:aeaada5cf60efe8d0e772d032fe3cc2bc613739c@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f AS bpf-builder
WORKDIR /go/src/github.com/cilium/tetragon
RUN apt-get update && apt-get install -y linux-libc-dev
COPY . ./
ARG TARGETARCH
RUN make tetragon-bpf LOCAL_CLANG=1 TARGET_ARCH=$TARGETARCH

# Second builder (cross-)compile tetragon and tetra
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.22.6@sha256:2bd56f00ff47baf33e64eae7996b65846c7cb5e0a46e0a882ef179fd89654afa AS tetragon-builder
WORKDIR /go/src/github.com/cilium/tetragon
ARG TETRAGON_VERSION TARGETARCH
COPY . .
RUN make VERSION=$TETRAGON_VERSION TARGET_ARCH=$TARGETARCH tetragon tetra tetragon-oci-hook tetragon-oci-hook-setup

# Third builder (cross-)compile a stripped gops
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.22.6-alpine@sha256:1a478681b671001b7f029f94b5016aed984a23ad99c707f6a0ab6563860ae2f3 AS gops
ARG TARGETARCH
RUN apk add --no-cache git \
# renovate: datasource=github-releases depName=google/gops
 && git clone --depth 1 --branch v0.3.28 https://github.com/google/gops /gops \
 && cd /gops \
 && GOARCH=$TARGETARCH go build -ldflags="-s -w" .

# This builder (cross-)compile a stripped static version of bpftool.
# This step was kept because the downloaded version includes LLVM libs with the
# disassembler that makes the static binary grow from ~2Mo to ~30Mo.
FROM --platform=$BUILDPLATFORM quay.io/cilium/clang:aeaada5cf60efe8d0e772d032fe3cc2bc613739c@sha256:b440ae7b3591a80ffef8120b2ac99e802bbd31dee10f5f15a48566832ae0866f AS bpftool-builder
WORKDIR /bpftool
ARG TARGETARCH BUILDARCH
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get update && echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse\n\
deb [arch=amd64] http://security.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse\n\
deb [arch=amd64] http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse\n\
deb [arch=amd64] http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse\n\
deb [arch=arm64] http://ports.ubuntu.com/ jammy main restricted universe multiverse\n\
deb [arch=arm64] http://ports.ubuntu.com/ jammy-updates main restricted universe multiverse\n\
deb [arch=arm64] http://ports.ubuntu.com/ jammy-security main restricted universe multiverse\n\
deb [arch=arm64] http://ports.ubuntu.com/ jammy-backports main restricted universe multiverse" > /etc/apt/sources.list \
    && dpkg --add-architecture arm64; fi
RUN apt-get update
RUN if [ $BUILDARCH != $TARGETARCH ]; \
    then apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libelf-dev:arm64 libcap-dev:arm64 crossbuild-essential-$TARGETARCH; \
    else apt-get install -y curl git llvm gcc pkg-config zlib1g-dev libelf-dev libcap-dev; fi
# v7.3.0
ENV BPFTOOL_REV="687e7f06f2ee104ed6515ec3a9816af77bfa7a17"
RUN git clone https://github.com/libbpf/bpftool.git . && git checkout ${BPFTOOL_REV} && git submodule update --init --recursive
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
FROM docker.io/library/alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5 AS base-build
RUN apk add iproute2
RUN mkdir /var/lib/tetragon/ && \
    mkdir -p /etc/tetragon/tetragon.conf.d/ && \
    mkdir -p /etc/tetragon/tetragon.tp.d/ && \
    apk add --no-cache --update bash
COPY --from=tetragon-builder /go/src/github.com/cilium/tetragon/tetragon /usr/bin/
COPY --from=tetragon-builder /go/src/github.com/cilium/tetragon/tetra /usr/bin/
COPY --from=tetragon-builder /go/src/github.com/cilium/tetragon/contrib/tetragon-rthooks/tetragon-oci-hook /usr/bin/
COPY --from=tetragon-builder /go/src/github.com/cilium/tetragon/contrib/tetragon-rthooks/tetragon-oci-hook-setup /usr/bin/
COPY --from=gops /gops/gops /usr/bin/
COPY --from=bpf-builder /go/src/github.com/cilium/tetragon/bpf/objs/*.o /var/lib/tetragon/
ENTRYPOINT ["/usr/bin/tetragon"]

# This target only builds with the `--target release` option and reduces the
# size of the final image with a static build of bpftool without the LLVM
# disassembler
FROM base-build AS release
COPY --from=bpftool-builder bpftool/src/bpftool /usr/bin/bpftool

FROM base-build
COPY --from=bpftool-downloader /bpftool /usr/bin/bpftool
