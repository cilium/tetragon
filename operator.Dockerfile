# syntax=docker/dockerfile:1.2

# Copyright 2020-2021 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE=scratch
ARG GOLANG_IMAGE=quay.io/cilium/cilium-builder:b7a9dcdcadd77d38db87bbd06b9bc238e9dab5a0@sha256:eecc017a6ccf0c7884f1ffcf10e58462a272f5e41c0ece09adb351e8839e3157
ARG ALPINE_IMAGE=docker.io/library/alpine:3.12.7@sha256:36553b10a4947067b9fbb7d532951066293a68eae893beba1d9235f7d11a20ad

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
ARG NOSTRIP

WORKDIR /go/src/github.com/cilium/tetragon
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/tetragon --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    make GOARCH=${TARGETARCH} tetragon-operator-image \
    && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv tetragon-operator /out/${TARGETOS}/${TARGETARCH}/usr/bin

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${ALPINE_IMAGE} as certs
RUN apk --update add ca-certificates

FROM ${BASE_IMAGE}
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/tetragon-operator /usr/bin/tetragon-operator
WORKDIR /
ENV GOPS_CONFIG_DIR=/
CMD ["/usr/bin/tetragon-operator"]
