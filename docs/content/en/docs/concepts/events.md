---
title: "Events"
weight: 1
description: "Documentation for Tetragon Events"
---

Tetragon's events are exposed to the system through either the gRPC
endpoint or JSON logs. Commands in this section assume the Getting
Started guide was used, but are general other than the namespaces
chosen and should work in most environments.

### JSON

The first way is to observe the raw json output from the stdout container log:

```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f
```

The raw JSON events provide Kubernetes API, identity metadata, and OS
level process visibility about the executed binary, its parent and the execution
time. A base Tetragon installation will produce `process_exec` and `process_exit`
events encoded in JSON as shown here,

<details><summary>Process execution event</summary>
<p>

```json
{
  "process_exec": {
    "process": {
      "exec_id": "Z2tlLWpvaG4tNjMyLWRlZmF1bHQtcG9vbC03MDQxY2FjMC05czk1OjEzNTQ4Njc0MzIxMzczOjUyNjk5",
      "pid": 52699,
      "uid": 0,
      "cwd": "/",
      "binary": "/usr/bin/curl",
      "arguments": "https://ebpf.io/applications/#tetragon",
      "flags": "execve rootcwd",
      "start_time": "2023-10-06T22:03:57.700327580Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://551e161c47d8ff0eb665438a7bcd5b4e3ef5a297282b40a92b7c77d6bd168eb3",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-10-06T21:52:41Z",
          "pid": 49
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        },
        "workload": "xwing"
      },
      "docker": "551e161c47d8ff0eb665438a7bcd5b4",
      "parent_exec_id": "Z2tlLWpvaG4tNjMyLWRlZmF1bHQtcG9vbC03MDQxY2FjMC05czk1OjEzNTQ4NjcwODgzMjk5OjUyNjk5",
      "tid": 52699
    },
    "parent": {
      "exec_id": "Z2tlLWpvaG4tNjMyLWRlZmF1bHQtcG9vbC03MDQxY2FjMC05czk1OjEzNTQ4NjcwODgzMjk5OjUyNjk5",
      "pid": 52699,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "arguments": "-c \"curl https://ebpf.io/applications/#tetragon\"",
      "flags": "execve rootcwd clone",
      "start_time": "2023-10-06T22:03:57.696889812Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://551e161c47d8ff0eb665438a7bcd5b4e3ef5a297282b40a92b7c77d6bd168eb3",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-10-06T21:52:41Z",
          "pid": 49
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        },
        "workload": "xwing"
      },
      "docker": "551e161c47d8ff0eb665438a7bcd5b4",
      "parent_exec_id": "Z2tlLWpvaG4tNjMyLWRlZmF1bHQtcG9vbC03MDQxY2FjMC05czk1OjEzNTQ4NjQ1MjQ1ODM5OjUyNjg5",
      "tid": 52699
    }
  },
  "node_name": "gke-john-632-default-pool-7041cac0-9s95",
  "time": "2023-10-06T22:03:57.700326678Z"
}

```
</p>
</details>

Will only highlight a few important fields here. For a full specification of events see the Reference
section. All events in Tetragon contain a `process_exec` block to identify the process generating the
event. For execution events this is the primary block. For [Tracing Policy]({{< ref "/docs/concepts/tracing-policy" >}}) events the
hook that generated the event will attach further data to this. The `process_exec` event provides
a cluster wide unique id the `process_exec.exec_id` for this process along with the metadata expected
in a Kubernetes cluster  `process_exec.process.pod`. The binary and args being executed are part of
the event here `process_exec.process.binary` and `process_exec.process.args`. Finally, a `node_name`
and `time` provide the location and time for the event and will be present in all event types.

A default deployment writes the JSON log to `/var/run/cilium/tetragon/tetragon.log` where it can
be exported through normal log collection tooling, e.g. 'fluentd', logstash, etc.. The file will
be rotated and compressed by default. See [Helm Options] for details on how to customize this location.

#### `tetra` CLI

A second way is to use the [`tetra`](https://github.com/cilium/tetragon/tree/main/cmd/tetra) CLI. This
has the advantage that it can also be used to filter and pretty print the output. The tool
allows filtering by process, pod, and other fields. To install tetra see the
[Tetra Installation Guide]({{< ref "/docs/installation/tetra-cli" >}})

To start printing events run:
```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact
```

The `tetra` CLI is also available inside `tetragon` container.

```shell
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```

This was used in the quick start and generates a pretty printing of the events, To further
filter by a specific binary and/or pod do the following,

```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact --processes curl --pod xwing
```

Will filter and report just the relevant events.

```
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon 60
```

### gRPC

In addition Tetragon can expose a gRPC endpoint listeners may attach to. The
gRPC is exposed by default helm install on `localhost:54321`, but the address
can be configured  with the `--server-address` option. This can be
set from helm with the `tetragon.grpc.address` flag or disabled completely if
needed with `tetragon.grpc.enabled`.

```shell
helm install tetragon cilium/tetragon -n kube-system --set tetragon.grpc.enabled=true --set tetragon.grpc.address=localhost:54321
```

An example gRPC endpoint is the Tetra CLI when its not piped JSON output directly,

```shell
 kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```
