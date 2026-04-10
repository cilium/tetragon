# Tetragon Development Container
#
# Provides a complete development environment for building, testing, and
# debugging Tetragon. Includes Go, Clang/LLVM for BPF compilation, and
# all required system libraries.
#
# Tool versions are kept in sync with CI (Makefile, Dockerfile, Dockerfile.clang).

FROM docker.io/library/golang:1.25.7-bookworm

ARG TARGETARCH

# ──────────────────────────────────────────────────────────────────────────────
# System packages required by Tetragon builds and tests
# (mirrors Dockerfile.dev + additions for interactive development)
# ──────────────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    pkg-config \
    # BPF / kernel development
    linux-libc-dev \
    libelf-dev \
    libcap-dev \
    zlib1g-dev \
    flex \
    bison \
    autoconf \
    bc \
    # Utilities used by Makefile / tests
    rpm2cpio \
    cpio \
    git \
    curl \
    wget \
    netcat-traditional \
    file \
    strace \
    jq \
    less \
    sudo \
    iproute2 \
    # Editor / IDE support
    vim \
    # Code navigation for BPF C code
    cscope \
    bear \
    # LLVM apt repository prerequisites
    lsb-release \
    software-properties-common \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# ──────────────────────────────────────────────────────────────────────────────
# Clang/LLVM 20 (matches Dockerfile.clang)
# Used for LOCAL_CLANG=1 BPF compilation
# ──────────────────────────────────────────────────────────────────────────────
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-20 main" \
      > /etc/apt/sources.list.d/llvm-20.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    clang-20 \
    libclang-common-20-dev \
    llvm-20 \
    llvm-20-runtime \
    llvm-20-linker-tools \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/lib/llvm-20/bin/clang /usr/bin/clang \
    && ln -sf /usr/lib/llvm-20/bin/llc /usr/bin/llc \
    && ln -sf /usr/bin/clang-format-18 /usr/bin/clang-format

# ──────────────────────────────────────────────────────────────────────────────
# bpftool (pre-built, with LLVM disassembler)
# Version matches Dockerfile: v7.2.0-snapshot.0
# ──────────────────────────────────────────────────────────────────────────────
ARG BPFTOOL_TAG=v7.2.0-snapshot.0
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_TAG}/bpftool-${BPFTOOL_TAG}-${ARCH}.tar.gz" \
      | tar xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/bpftool

# ──────────────────────────────────────────────────────────────────────────────
# golangci-lint (matches Makefile: v2.9.0)
# ──────────────────────────────────────────────────────────────────────────────
ARG GOLANGCILINT_VERSION=v2.9.0
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh \
      | sh -s -- -b /usr/local/bin ${GOLANGCILINT_VERSION}

# ──────────────────────────────────────────────────────────────────────────────
# Go tools for development
# ──────────────────────────────────────────────────────────────────────────────
RUN go install golang.org/x/tools/cmd/goimports@latest && \
    go install github.com/google/gops@v0.3.29 && \
    go clean -cache -modcache

# ──────────────────────────────────────────────────────────────────────────────
# Kubernetes development tools (optional, for e2e / kind workflows)
# ──────────────────────────────────────────────────────────────────────────────
RUN curl -fsSL https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/$(dpkg --print-architecture)/kubectl \
      -o /usr/local/bin/kubectl && chmod +x /usr/local/bin/kubectl && \
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash && \
    curl -fsSL -o /usr/local/bin/kind \
      "https://kind.sigs.k8s.io/dl/v0.25.0/kind-linux-$(dpkg --print-architecture)" && \
    chmod +x /usr/local/bin/kind

# ──────────────────────────────────────────────────────────────────────────────
# Runtime directories expected by Tetragon
# ──────────────────────────────────────────────────────────────────────────────
RUN mkdir -p /var/lib/tetragon && \
    mkdir -p /etc/tetragon/tetragon.conf.d && \
    mkdir -p /etc/tetragon/tetragon.tp.d

# Default workspace
WORKDIR /workspaces/tetragon
