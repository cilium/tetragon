# SPDX-License-Identifier: Apache-2.0

# Bakes static tester-progs binaries into a busybox image for e2e workloads.
# PROGS lists the tester sources (<name>.c each) to compile statically.
# Build with: make image-tester-progs (context: contrib/tester-progs).
FROM gcc:14@sha256:df8990c2f53aa9ef57808e755aa8f580dd86b9b34c6233715de23e89f7e06b65 AS build
ARG PROGS="uprobe-simple"
WORKDIR /src
# Sources only; keep locally built tester binaries out of the image.
COPY *.c *.h ./
RUN test -n "$PROGS" && mkdir -p /out && \
    for p in $PROGS; do \
        gcc -Wall -O0 -static -no-pie -o "/out/$p" "$p.c" || exit 1; \
    done

FROM busybox:1.37@sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028
COPY --from=build /out/ /usr/bin/
