# Bakes the uprobe-simple tester binary (symbol `pizza` at /usr/bin/uprobe-simple)
# for the resolvePathInContainer e2e test. Build context: contrib/tester-progs.
FROM gcc:14 AS build
COPY uprobe-simple.c /uprobe-simple.c
RUN gcc -O0 -static -no-pie -o /uprobe-simple /uprobe-simple.c

FROM busybox:1.37
COPY --from=build /uprobe-simple /usr/bin/uprobe-simple
