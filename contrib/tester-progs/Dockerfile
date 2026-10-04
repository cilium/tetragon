# SPDX-License-Identifier: Apache-2.0

# Workload image for the uprobe resolvePathInContainer e2e test. uprobe-simple
# is linked statically, and BusyBox supplies the shell the workload loops with.
# The build context is this directory; build with: make image-tester-progs
FROM docker.io/library/golang:1.26.5@sha256:079e59808d2d252516e27e3f3a9c003740dee7f75e55aa71528766d52bcfc16a AS build
WORKDIR /src
COPY uprobe-simple.c .
RUN gcc -Wall -static -fno-inline uprobe-simple.c -o uprobe-simple

FROM docker.io/library/busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0
COPY --from=build /src/uprobe-simple /usr/bin/uprobe-simple
