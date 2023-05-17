---
title: "Deploy as a container"
linkTitle: "Container"
icon: "tutorials"
weight: 2
description: "Install and manage Tetragon as a container without a Kubernetes cluster"
---

## Install

### Stable versions

To run a stable version, please check [Tetragon quay repository](https://quay.io/cilium/tetragon?tab=tags)
and select which version you want. For example if you want to run the latest
version which is `{{< latest-version >}}` currently.

```shell
docker run --name tetragon --rm -d                   \
    --pid=host --cgroupns=host --privileged          \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
    quay.io/cilium/tetragon:{{< latest-version >}}
```

### Unstable-development versions

To run unstable development versions of Tetragon, use the
`latest` tag from [Tetragon-CI quay repository](https://quay.io/repository/cilium/tetragon-ci?tab=tags).
This will run the image that was built from the latest commit available on the
Tetragon main branch.

```shell
docker run --name tetragon --rm -d                  \
   --pid=host --cgroupns=host --privileged          \
   -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf \
   quay.io/cilium/tetragon-ci:latest
```

{{< note >}}
If Tetragon does not to start due to BTF issues, please refer to the
[corresponding question in the FAQ]({{< ref "/docs/faq/#tetragon-failed-to-start-complaining-about-a-missing-btf-file" >}})
for details and solutions.
{{< /note >}}

## What's next

- See [Explore security observability events](/docs/getting-started/explore-security-observability-events/)
to learn how to see the Tetragon events.
