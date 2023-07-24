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
If Tetragon does not start due to BTF issues, please refer to the
[corresponding question in the FAQ]({{< ref "/docs/faq/#tetragon-failed-to-start-complaining-about-a-missing-btf-file" >}})
for details and solutions.
{{< /note >}}

## Configuration

There are multiple ways to change the default configuration options:

1. Append Tetragon controlling settings at the end of the command

    As an example set the file where to export JSON events with `--export-filename` argument:
    ```shell
    docker run --name tetragon --rm -d \
        --pid=host --cgroupns=host --privileged \
        -v /sys/kernel:/sys/kernel \
        quay.io/cilium/tetragon:{{< latest-version >}} \
        /usr/bin/tetragon --export-filename /var/log/tetragon/tetragon.log
    ```

    For a complete list of CLI arguments, please check [Tetragon daemon configuration](/docs/reference/tetragon-configuration).


2. Set the controlling settings using environment variables

    ```shell
    docker run --name tetragon --rm -d \
        --pid=host --cgroupns=host --privileged \
        --env "TETRAGON_EXPORT_FILENAME=/var/log/tetragon/tetragon.log" \
        -v /sys/kernel:/sys/kernel \
        quay.io/cilium/tetragon:{{< latest-version >}}
    ```

    Every controlling setting can be set using environment variables. Prefix it with the key word `TETRAGON_` then upper case the controlling setting. As an example to set where to export JSON events: `--export-filename` will be `TETRAGON_EXPORT_FILENAME`.

    For a complete list of all controlling settings, please check [tetragon daemon configuration](/docs/reference/tetragon-configuration).

3. Set controlling settings from configuration files mounted as volumes

    On the host machine set the configuration drop-ins inside `/etc/tetragon/tetragon.conf.d/` directory according to the [configuration examples](/docs/reference/tetragon-configuration/#configuration-examples), then mount it as volume:

    ```shell
    docker run --name tetragon --rm -d \
        --pid=host --cgroupns=host --privileged \
        -v /sys/kernel:/sys/kernel \
        -v /etc/tetragon/tetragon.conf.d/:/etc/tetragon/tetragon.conf.d/ \
        quay.io/cilium/tetragon:{{< latest-version >}}
    ```

    This will map the `/etc/tetragon/tetragon.conf.d/` drop-in directory from the host into the container.

See [Tetragon daemon configuration](/docs/reference/tetragon-configuration) reference for further details.

## What's next

- See [Explore security observability events](/docs/getting-started/explore-security-observability-events/)
to learn how to see the Tetragon events.
