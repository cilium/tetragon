---
title: "Quick Local Docker Install"
weight: 2
description: "Discover and experiment with Tetragon on your local Linux host"
---

{{< note >}}
This guide has been tested on Ubuntu 22.04 and 22.10 with respectively kernel
`5.15.0` and `5.19.0` on amd64 and arm64 but
[any recent distribution](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere)
shipping with a relatively recent kernel should work. See the FAQ for further details on
the [recommended kernel versions]({{< ref "/docs/faq#what-is-the-minimum-linux-kernel-version-to-run-tetragon" >}}).

Note that you cannot run Tetragon using Docker Desktop on macOS because of a
limitation of the Docker Desktop Linux virtual machine. Learn more about this issue
and how to run Tetragon on a Mac computer in [this section of the FAQ page](/docs/faq/#can-i-run-tetragon-on-mac-computers).
{{< /note >}}

## Start Tetragon

The easiest way to start experimenting with Tetragon is to run it via Docker
using the released container images.

```shell-session
docker run --name tetragon-container --rm --pull always \
    --pid=host --cgroupns=host --privileged             \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf    \
    quay.io/cilium/tetragon-ci:latest
```

This will start Tetragon in a privileged container. Priviliges are required
to load and attach BPF programs. See Installation section for more details.

## What's Next

Check for [execution events]({{< ref "/docs/getting-started/execution" >}}).
