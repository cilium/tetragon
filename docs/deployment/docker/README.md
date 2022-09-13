# Docker Deployment

This document will help you get started with Tetragon without having to deploy a Kubernetes cluster.

## BTF Requirement

The base kernel should support [BTF](../../../README.md#btf-requirement) or a BTF file should
be bind mounted on top of `/var/lib/tetragon/btf` inside container.

To check if BTF is enabled on your Linux host system check for the BTF file
in the standard location:

```
$ ls /sys/kernel/btf/
```

## Deployment

### Stable versions

To run a stable version, please check [Tetragon quay repository](https://quay.io/cilium/tetragon?tab=tags)
and select which version you want.

Example:

```
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

```
docker run --name tetragon \
   --rm -it -d --pid=host \
   --cgroupns=host --privileged \
   -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
   quay.io/cilium/tetragon-ci:latest \
   bash -c "/usr/bin/tetragon"
```


## Tetragon Events

To get Tetragon events, run the `tetra` binary that is shipped within Tetragon image:

```
docker exec -it tetragon \
   bash -c "/usr/bin/tetra getevents -o compact"
```
