# SPDX-License-Identifier: Apache-2.0

# Builds the complete tester-progs payload through its canonical Makefile.
# The repository root is the build context because Go helpers use the root Go
# module and vendor tree. Build with: make image-tester-progs.
FROM docker.io/library/golang:1.26.5@sha256:079e59808d2d252516e27e3f3a9c003740dee7f75e55aa71528766d52bcfc16a AS build
ARG TARGETARCH
WORKDIR /go/src/github.com/cilium/tetragon

# tester-progs includes native C and Go binaries, a static 32-bit binary,
# libcap users, and programs whose BTF sidecars require pahole/llvm-objcopy.
RUN set -eux; \
    case "$TARGETARCH" in \
        amd64) arch_packages="gcc-multilib" ;; \
        arm64) arch_packages="gcc-arm-linux-gnueabihf libc6-dev-armhf-cross" ;; \
        *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        dwarves \
        libcap-dev \
        llvm \
        $arch_packages; \
    if ! command -v llvm-objcopy >/dev/null; then \
        ln -s "$(ls /usr/bin/llvm-objcopy-* | head -n1)" /usr/local/bin/llvm-objcopy; \
    fi; \
    rm -rf /var/lib/apt/lists/*

COPY . ./
RUN make -C contrib/tester-progs clean && \
    make -C contrib/tester-progs -j"$(nproc)" && \
    mkdir -p /out && \
    cd contrib/tester-progs && \
    cp $(make -s all-files) /out/

# The Makefile produces glibc-linked executables, including libcap users and
# binaries which find libuprobe.so/libtester.so through a $ORIGIN rpath.
FROM docker.io/library/debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2
RUN apt-get update && \
    apt-get install -y --no-install-recommends libcap2 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /usr/bin/
