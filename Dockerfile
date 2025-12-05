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
RUN apt-get update && apt-get install -y linux-libc-dev gzip
COPY . ./
ARG TARGETARCH
ARG COMPRESS_BPF
RUN make tetragon-bpf LOCAL_CLANG=1 TARGET_ARCH=$TARGETARCH
RUN if [ "$COMPRESS_BPF" = "gzip" ]; then gzip bpf/objs/*.o; fi

# Second builder (cross-)compile tetragon and tetra
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.25.5@sha256:20b91eda7a9627c127c0225b0d4e8ec927b476fa4130c6760928b849d769c149 AS tetragon-builder
WORKDIR /go/src/github.com/cilium/tetragon
ARG TETRAGON_VERSION TARGETARCH
COPY . .
RUN make VERSION=$TETRAGON_VERSION TARGET_ARCH=$TARGETARCH tetragon tetra

# Third builder (cross-)compile a stripped gops
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.25.5-alpine@sha256:26111811bc967321e7b6f852e914d14bede324cd1accb7f81811929a6a57fea9 AS gops
ARG TARGETARCH
RUN apk add --no-cache git \
# renovate: datasource=github-releases depName=google/gops
 && git clone --depth 1 --branch v0.3.28 https://github.com/google/gops /gops \
 && cd /gops \
 && GOARCH=$TARGETARCH go build -ldflags="-s -w" .

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

# Get bash-completion manifests and generate tetra CLI bash
# autocompletions (we don't want all bash-completions in the base-build)
FROM docker.io/library/alpine:3.23.0@sha256:51183f2cfa6320055da30872f211093f9ff1d3cf06f39a0bdb212314c5dc7375 AS cli-autocomplete
COPY --from=tetragon-builder /go/src/github.com/cilium/tetragon/tetra /usr/bin/
RUN apk add --no-cache bash-completion && \
    tetra completion bash > /etc/bash_completion.d/tetra && \
    chmod a+r /etc/bash_completion.d/tetra

# Almost final step runs on target platform (might need emulation) and
# retrieves (cross-)compiled binaries from builders
FROM docker.io/library/alpine:3.23.0@sha256:51183f2cfa6320055da30872f211093f9ff1d3cf06f39a0bdb212314c5dc7375 AS base-build
RUN apk add --no-cache iproute2
RUN mkdir /var/lib/tetragon/ && \
    mkdir -p /etc/tetragon/tetragon.conf.d/ && \
    mkdir -p /etc/tetragon/tetragon.tp.d/ && \
    apk add --no-cache --update bash
COPY --from=tetragon-builder /go/src/github.com/cilium/tetragon/tetragon /usr/bin/
COPY --from=tetragon-builder /go/src/github.com/cilium/tetragon/tetra /usr/bin/
COPY --from=gops /gops/gops /usr/bin/
COPY --from=bpf-builder /go/src/github.com/cilium/tetragon/bpf/objs/* /var/lib/tetragon/
COPY --from=cli-autocomplete /etc/bash/bash_completion.sh /etc/bash/bash_completion.sh
COPY --from=cli-autocomplete /etc/bash_completion.d/000_bash_completion_compat.bash /etc/bash_completion.d/000_bash_completion_compat.bash
COPY --from=cli-autocomplete /etc/bash_completion.d/tetra /etc/bash_completion.d/tetra
COPY --from=cli-autocomplete /usr/share/bash-completion/bash_completion /usr/share/bash-completion/bash_completion
COPY --from=cli-autocomplete /usr/share/bash-completion/completions/ip /usr/share/bash-completion/completions/ip
ENTRYPOINT ["/usr/bin/tetragon"]

# This target only builds with the `--target release` option and reduces the
# size of the final image with a static build of bpftool without the LLVM
# disassembler
FROM base-build AS release
COPY --from=bpftool-builder bpftool/src/bpftool /usr/bin/bpftool

FROM base-build
COPY --from=bpftool-downloader /bpftool /usr/bin/bpftool
