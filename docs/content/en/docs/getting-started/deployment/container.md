---
title: "Container deployment"
weight: 1
description: "Install Tetragon as a container without a Kubernetes cluster"
---

## BTF Requirement

The base kernel should support BTF or a BTF file should be bind mounted on top
of `/var/lib/tetragon/btf` inside container.

To check if BTF is enabled on your Linux host system check for the BTF file in
the standard location:

```shell
ls /sys/kernel/btf/
```

## Deployment

### Stable versions

To run a stable version, please check [Tetragon quay
repository](https://quay.io/cilium/tetragon?tab=tags) and select which version
you want.

Example:

```shell
docker run --name tetragon \
   --rm -it -d --pid=host \
   --cgroupns=host --privileged \
   -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
   quay.io/cilium/tetragon:v0.8.0 \
   bash -c "/usr/bin/tetragon"
```

### Unstable Development versions

To run unstable development versions of Tetragon, use the
`latest` tag from [Tetragon-CI quay
repository](https://quay.io/repository/cilium/tetragon-ci?tab=tags).

Example:

```shell
docker run --name tetragon \
   --rm -it -d --pid=host \
   --cgroupns=host --privileged \
   -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
   quay.io/cilium/tetragon-ci:latest
```

## What's next

See [Explore security observability events](/docs/getting-started/explore-security-observability-events/)
to learn how to see the Tetragon events.

