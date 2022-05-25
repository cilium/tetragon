FROM quay.io/isovalent/hubble-llvm:2022-01-03-a6dfdaf as bpf-builder
WORKDIR /go/src/github.com/cilium/tetragon
RUN apt-get update
RUN apt-get install -y linux-libc-dev
COPY . ./
RUN make tetragon-bpf LOCAL_CLANG=1

FROM quay.io/isovalent/hubble-libbpf:v0.2.3 as hubble-libbpf
WORKDIR /go/src/github.com/cilium/tetragon
COPY . ./

FROM quay.io/cilium/cilium-builder:b7a9dcdcadd77d38db87bbd06b9bc238e9dab5a0@sha256:eecc017a6ccf0c7884f1ffcf10e58462a272f5e41c0ece09adb351e8839e3157 as hubble-builder
WORKDIR /go/src/github.com/cilium/tetragon
RUN apt-get update && apt-get install -y libelf-dev zlib1g-dev
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0.2.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.a /usr/local/lib/
RUN ldconfig /usr/local/
COPY . ./
RUN make tetragon-image LOCAL_CLANG=1

FROM docker.io/library/golang:1.17.8-alpine3.15@sha256:b35984144ec2c2dfd6200e112a9b8ecec4a8fd9eff0babaff330f1f82f14cb2a as gops
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

FROM docker.io/library/alpine:3.15.4@sha256:a777c9c66ba177ccfea23f2a216ff6721e78a662cd17019488c417135299cd89
RUN apk add iproute2
RUN addgroup hubble	     && \
    mkdir /var/lib/tetragon/ && \
    apk add --no-cache --update bash
COPY --from=bpftool-builder /src/linux/tools/bpf/bpftool/bpftool /usr/bin/bpftool
COPY --from=hubble-builder /go/src/github.com/cilium/tetragon/tetragon /usr/bin/
COPY --from=hubble-builder /go/src/github.com/cilium/tetragon/tetra /usr/bin/
COPY --from=gops /go/bin/gops /bin /usr/bin/
COPY --from=bpf-builder /go/src/github.com/cilium/tetragon/bpf/objs/*.o /var/lib/tetragon/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0.2.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so.0 /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.so /usr/local/lib/
COPY --from=hubble-libbpf /go/src/github.com/covalentio/hubble-fgs/src/libbpf.a /usr/local/lib/
