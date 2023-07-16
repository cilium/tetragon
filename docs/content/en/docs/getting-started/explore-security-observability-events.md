---
title: "Explore security observability events"
weight: 5
icon: "reference"
description: "Learn how to start exploring the Tetragon events"
---

There are two ways to observer Tetragon events, either the raw JSON output from
Tetragon logs directly, or using the [`tetra`](https://github.com/cilium/tetragon/tree/main/cmd/tetra)
client CLI to pretty print events, filter by process, pod, and other fields.

The `tetra` client CLI is particulary useful to interact with Tetragon from the host
without entering the container, from a remote host, a macOS or a Windows system. Fo such
cases please follow the [Install tetra CLI](/docs/getting-started/install-tetra-cli) guide
before continuing.

This guide is splitted by deployment method since every deployment can have its own way
on how to explore the raw JSON logs.

## Kubernetes deployment

After Tetragon and the [demo application is up and
running](/docs/getting-started/kubernetes-quickstart-guide/#deploy-the-demo-application)
you can examine the security and observability events produced by Tetragon in
different ways.

### Raw JSON events

The first way is to observe the raw json output from the stdout container log:

```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f
```

The raw JSON events provide Kubernetes API, identity metadata, and OS
level process visibility about the executed binary, its parent and the execution
time.

### `tetra` CLI

The `tetra` CLI is already available inside `tetragon` container.

```shell
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```

Otherwise after [installing `tetra` CLI](/docs/getting-started/install-tetra-cli), it is possible
to explore events without entering `tetragon` container:

1. On the same host without entering `tetragon` container:

   ```shell
   kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact
   ```
