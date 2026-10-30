# Tetragon Development Container
#
# Provides a complete development environment for building, testing, and
# debugging Tetragon. Includes Go, Clang/LLVM for BPF compilation, and
# all required system libraries.
#
# Tool versions are kept in sync with CI (Makefile, Dockerfile, Dockerfile.clang).

FROM docker.io/library/golang:1.27.3-bookworm

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
    dwarves \
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
    # 32-bit enforcer-tester in contrib/tester-progs (as in Dockerfile.tester-progs)
    $(case "$(dpkg --print-architecture)" in \
        amd64) echo gcc-multilib ;; \
        arm64) echo gcc-arm-linux-gnueabihf libc6-dev-armhf-cross ;; \
      esac) \
    # Editor / IDE support
    vim \
    # Code navigation for BPF C code
    cscope \
    bear \
    # LLVM apt repository prerequisites
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Keep the image PATH (Go) in login shells, which the devcontainer tools use to
# probe the environment. Same fix as the devcontainers common-utils feature.
RUN sed -i -E 's/((^|\s)PATH=)([^\$]*)$/\1${PATH:-\3}/g' /etc/profile

# ──────────────────────────────────────────────────────────────────────────────
# Clang/LLVM 22 (matches Dockerfile.clang and Dockerfile.clang-format)
# Used for LOCAL_CLANG=1 BPF compilation
# ──────────────────────────────────────────────────────────────────────────────
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-22 main" \
      > /etc/apt/sources.list.d/llvm-22.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    clang-22 \
    clang-format-22 \
    libclang-common-22-dev \
    llvm-22 \
    llvm-22-runtime \
    llvm-22-linker-tools \
    && rm -rf /var/lib/apt/lists/* \
    && for t in clang llc clang-format llvm-objcopy; do ln -sf /usr/lib/llvm-22/bin/$t /usr/bin/$t; done

ENV LOCAL_CLANG=1 LOCAL_CLANG_FORMAT=1

# ──────────────────────────────────────────────────────────────────────────────
# bpftool (pre-built, with LLVM disassembler), version as in Dockerfile
# ──────────────────────────────────────────────────────────────────────────────
ARG BPFTOOL_TAG=v7.8.1
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_TAG}/bpftool-${BPFTOOL_TAG}-${ARCH}.tar.gz" \
      | tar xz -C /usr/local/bin && \
    chmod +x /usr/local/bin/bpftool

# ──────────────────────────────────────────────────────────────────────────────
# golangci-lint, same image as GOLANGCILINT_IMAGE in the Makefile
# ──────────────────────────────────────────────────────────────────────────────
COPY --from=docker.io/golangci/golangci-lint:v2.15.0@sha256:fbfcfd12a6f8d7f1b97b3362ca80fc2a244d46863148c73cb88e7793af96c481 \
    /usr/bin/golangci-lint /usr/local/bin/golangci-lint

# ──────────────────────────────────────────────────────────────────────────────
# Go tools for development
# ──────────────────────────────────────────────────────────────────────────────
RUN go install github.com/google/gops@v0.3.29 && \
    go clean -cache -modcache

# ──────────────────────────────────────────────────────────────────────────────
# Kubernetes development tools (optional, for e2e / kind workflows)
# Versions as in .github/workflows/run-e2e-tests.yaml
# ──────────────────────────────────────────────────────────────────────────────
RUN ARCH=$(dpkg --print-architecture) && \
    curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.37.1/bin/linux/${ARCH}/kubectl" && \
    curl -fsSL "https://get.helm.sh/helm-v4.3.1-linux-${ARCH}.tar.gz" \
      | tar xz -C /usr/local/bin --strip-components=1 "linux-${ARCH}/helm" && \
    curl -fsSL -o /usr/local/bin/kind "https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-${ARCH}" && \
    chmod +x /usr/local/bin/kubectl /usr/local/bin/kind

# ──────────────────────────────────────────────────────────────────────────────
# Runtime directories expected by Tetragon
# ──────────────────────────────────────────────────────────────────────────────
RUN mkdir -p /var/lib/tetragon /etc/tetragon/tetragon.conf.d /etc/tetragon/tetragon.tp.d
