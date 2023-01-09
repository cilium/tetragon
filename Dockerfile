FROM quay.io/cilium/clang:7ea8dd5b610a8864ce7b56e10ffeb61030a0c50e@sha256:02ad7cc1d08d85c027557099b88856945be5124b5c31aeabce326e7983e3913b as bpf-builder
WORKDIR /go/src/github.com/cilium/tetragon
RUN apt-get update
RUN apt-get install -y linux-libc-dev
COPY . ./
RUN make tetragon-bpf LOCAL_CLANG=1

FROM quay.io/cilium/cilium-builder:a2dc3278c48e1593b1f6c8fd9e5c6a982d56a875@sha256:98c4e694805e9a9d410ed73d555e97e91d77e2ab4529b6b51f5243b33ab411b1 as hubble-builder
ARG TETRAGON_VERSION
WORKDIR /go/src/github.com/cilium/tetragon
RUN apt-get update && apt-get install -y libelf-dev zlib1g-dev
COPY . ./
RUN make tetragon-image LOCAL_CLANG=1 VERSION=$TETRAGON_VERSION

FROM docker.io/library/golang:1.19.2-alpine3.15@sha256:af65c2761458722a028131c06edbdff97d6efcd2d66630fbfe0572b18185c7a4 as gops
RUN apk add --no-cache binutils git \
 && git clone https://github.com/google/gops /go/src/github.com/google/gops \
 && cd /go/src/github.com/google/gops \
 && git checkout -b v0.3.22 v0.3.22 \
 && go install \
 && strip /go/bin/gops

# Mostly copied from https://github.com/cilium/image-tools/blob/master/images/bpftool
FROM quay.io/cilium/image-compilers:c1ba0665b6f9f012d014a642d9882f7c38bdf365@sha256:01c7c957e9b0fc200644996c6bedac297c98b81dea502a3bc3047837e67a7fcb as bpftool-builder
ENV REV "5e22dd18626726028a93ff1350a8a71a00fd843d"
RUN curl --fail --show-error --silent --location "https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf-next/+archive/${REV}.tar.gz" --output /tmp/linux.tgz
RUN mkdir -p /src/linux
RUN tar -xf /tmp/linux.tgz -C /src/linux
RUN rm -f /tmp/linux.tgz
WORKDIR /src/linux/tools/bpf/bpftool
RUN make -j $(nproc) LDFLAGS=-static
RUN strip bpftool

FROM docker.io/library/alpine:3.17.1@sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a
RUN apk add iproute2
RUN mkdir /var/lib/tetragon/ && \
    apk add --no-cache --update bash
COPY --from=bpftool-builder /src/linux/tools/bpf/bpftool/bpftool /usr/bin/bpftool
COPY --from=hubble-builder /go/src/github.com/cilium/tetragon/tetragon /usr/bin/
COPY --from=hubble-builder /go/src/github.com/cilium/tetragon/tetra /usr/bin/
COPY --from=gops /go/bin/gops /bin /usr/bin/
COPY --from=bpf-builder /go/src/github.com/cilium/tetragon/bpf/objs/*.o /var/lib/tetragon/
