---
title: "Quick Local Docker Install"
weight: 2
description: "Discover and experiment with Tetragon on your local Linux host"
aliases: ["/docs/tutorials/try-tetragon-linux"]
---

{{< note >}}
This guide has been tested on Ubuntu 22.04 and 22.10 with respectively kernel
`5.15.0` and `5.19.0` on amd64 and arm64 but
[any recent distribution](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere)
shipping with a relatively recent kernel should work. See the FAQ for further details on
the [recommended kernel versions]({{< ref "/docs/installation/faq#what-is-the-minimum-linux-kernel-version-to-run-tetragon" >}}).

Note that you cannot run Tetragon using Docker Desktop on macOS because of a
limitation of the Docker Desktop Linux virtual machine. Learn more about this issue
and how to run Tetragon on a Mac computer in [this section of the FAQ page](/docs/installation/faq#can-i-run-tetragon-on-mac-computers).
{{< /note >}}

## Start Tetragon

The easiest way to start experimenting with Tetragon is to run it via Docker
using the released container images.

```shell
docker run -d --name tetragon --rm --pull always \
    --pid=host --cgroupns=host --privileged             \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf    \
    quay.io/cilium/tetragon:{{< latest-version >}}
```

This will start Tetragon in a privileged container running in the background.
Running Tetragon as a privileged container is required to load and attach BPF
programs. See the [Installation and Configuration]({{< ref "/docs/installation" >}})
section for more details.

## Run demo application

To explore Tetragon it is helpful to have a sample workload. You can use Cilium’s
demo application with [this Docker Compose file](https://github.com/cilium/tetragon/blob/main/examples/quickstart/docker-compose.yaml),
but any workload would work equally well:

```shell
curl -LO https://github.com/cilium/tetragon/raw/main/examples/quickstart/docker-compose.yaml
docker compose -f docker-compose.yaml up -d
```

You can use `docker container ls` to verify that the containers are up and
running. It might take a short amount of time for the container images to
download.

```shell
CONTAINER ID   IMAGE                             COMMAND                  CREATED          STATUS          PORTS                                   NAMES
cace79752d94   quay.io/cilium/json-mock:v1.3.8   "bash /run.sh"           34 seconds ago   Up 33 seconds                                           starwars-xwing-1
4f8422b43b5b   quay.io/cilium/json-mock:v1.3.8   "bash /run.sh"           34 seconds ago   Up 33 seconds                                           starwars-tiefighter-1
7b60618ca8bd   quay.io/cilium/starwars:v2.1      "/starwars-docker --…"   34 seconds ago   Up 33 seconds   0.0.0.0:8080->80/tcp, :::8080->80/tcp   starwars-deathstar-1
```

## What's next

Check for [execution events]({{< ref "/docs/getting-started/execution" >}}).
