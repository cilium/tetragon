---
title: "Explore security observability events"
weight: 3
description: "Learn how to start exploring the Tetragon events"
---

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

A second way is to pretty print the events using the
[`tetra`](https://github.com/cilium/tetragon/tree/main/cmd/tetra) CLI. The tool
also allows filtering by process, pod, and other fields.

If you are using `homebrew`, you can install the latest release with:
```shell
brew install tetra
```

Or you can download and install the latest release with the following commands:

```shell
GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
curl -L --remote-name-all https://github.com/cilium/tetragon/releases/latest/download/tetra-${GOOS}-${GOARCH}.tar.gz{,.sha256sum}
sha256sum --check tetra-${GOOS}-${GOARCH}.tar.gz.sha256sum
sudo tar -C /usr/local/bin -xzvf tetra-${GOOS}-${GOARCH}.tar.gz
rm tetra-${GOOS}-${GOARCH}.tar.gz{,.sha256sum}
```

See the [latest release
page](https://github.com/cilium/tetragon/releases/latest) for supported
`GOOS`/`GOARCH` binary releases.

To start printing events run:
```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact
```

The `tetra` CLI is also available inside `tetragon` container.

```shell
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```

### What's next

- [Tetragon events](/docs/tetragon-events/): Learn about the detail of events.
