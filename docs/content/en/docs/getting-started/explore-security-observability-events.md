---
title: "Explore Security Observability Events"
weight: 5
icon: "reference"
description: "Learn how to start exploring the Tetragon events"
---

There are two ways to quicly observer Tetragon events, either the raw JSON output from
Tetragon logs directly, or using the [`tetra`](https://github.com/cilium/tetragon/tree/main/cmd/tetra)
client CLI to pretty print events, filter by process, pod, and other fields.

The `tetra` client CLI is particulary useful to interact with Tetragon from the host
without entering the container, from a remote host, a macOS or a Windows system. Fo such
cases please follow the [Install tetra CLI](/docs/getting-started/install-tetra-cli) guide
before continuing.

This guide is splitted by deployment methods since every deployment can have its own way
on how to explore the raw JSON logs.

## Kubernetes deployment

After Tetragon and the [demo application is up and
running](/docs/getting-started/kubernetes-quickstart-guide/#deploy-the-demo-application)
you can examine the security and observability events produced by Tetragon in
different ways.

Tetragon by default monitors [Process lifecycle](/docs/use-cases/process-lifecycle) which
can be observed with the Tetragon [`process_exec`](https://deploy-preview-1237--tetragon.netlify.app/docs/reference/grpc-api/#processexec) and [  `process_exit`](https://deploy-preview-1237--tetragon.netlify.app/docs/reference/grpc-api/#processexit) JSON events.
These events contain the full lifecycle of processes, from fork/exec to
exit, including metadata such as:

* Binary name: Defines the name of an executable file
* Parent process: Helps to identify process execution anomalies (e.g., if a nodejs app forks a shell, this is suspicious)
* Command-line argument: Defines the program runtime behavior
* Current working directory: Helps to identify hidden malware execution from a temporary folder, which is a common pattern used in malwares
* Kubernetes metadata: Contains pods, labels, and Kubernetes namespaces, which are critical to identify service owners, particularly in a multitenant environments
* exec_id: A unique process identifier that correlates all recorded activity of a process


In another terminal, let's `kubectl exec` into the `xwing` pod and execute some example commands:

```bash
kubectl exec -it xwing -- /bin/bash
whoami
```

### Raw JSON events

The first way is to observe the raw json output from the stdout container log:

```shell
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f
```

Which will inlude the following events:
```json
{
  "process_exec": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjExNDI4NjE1NjM2OTAxOjUxNTgz",
      "pid": 51583,
      "uid": 0,
      "cwd": "/",
      "binary": "/usr/bin/whoami",
      "arguments": "--version",
      "flags": "execve rootcwd clone",
      "start_time": "2022-05-11T12:54:45.615Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2022-05-11T10:07:33Z",
          "pid": 50
        }
      },
      "docker": "1fb931d2f6e5e4cfdbaf30fdb8e2fdd",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkyMjU2MjMyNjk6NDM4NzI=",
      "refcnt": 1
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkyMjU2MjMyNjk6NDM4NzI=",
      "pid": 43872,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2022-05-11T12:15:36.225Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2022-05-11T10:07:33Z",
          "pid": 43
        }
      },
      "docker": "1fb931d2f6e5e4cfdbaf30fdb8e2fdd",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkxODU5NTMzOTk6NDM4NjE=",
      "refcnt": 1
    }
  },
  "node_name": "kind-control-plane",
  "time": "2022-05-11T12:54:45.615Z"
}
```

```json
{
  "process_exit": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjExNDI4NjE1NjM2OTAxOjUxNTgz",
      "pid": 51583,
      "uid": 0,
      "cwd": "/",
      "binary": "/usr/bin/whoami",
      "arguments": "--version",
      "flags": "execve rootcwd clone",
      "start_time": "2022-05-11T12:54:45.615Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2022-05-11T10:07:33Z",
          "pid": 50
        }
      },
      "docker": "1fb931d2f6e5e4cfdbaf30fdb8e2fdd",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkyMjU2MjMyNjk6NDM4NzI="
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkyMjU2MjMyNjk6NDM4NzI=",
      "pid": 43872,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2022-05-11T12:15:36.225Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1fb931d2f6e5e4cfdbaf30fdb8e2fdd81320bdb3047ded50120a4f82838209ce",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2022-05-11T10:07:33Z",
          "pid": 43
        }
      },
      "docker": "1fb931d2f6e5e4cfdbaf30fdb8e2fdd",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjkwNzkxODU5NTMzOTk6NDM4NjE="
    }
  },
  "node_name": "kind-control-plane",
  "time": "2022-05-11T12:54:45.616Z"
}
```

Using the [`jq`](https://jqlang.github.io/jq/) tool it is possible to filter by the
[`process_exec`](https://deploy-preview-1237--tetragon.netlify.app/docs/reference/grpc-api/#processexec) and [`process_exit`](https://deploy-preview-1237--tetragon.netlify.app/docs/reference/grpc-api/#processexit) events from the `xwing` pod:
```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | jq 'select(.process_exec.process.pod.name=="xwing" or .process_exit.process.pod.name=="xwing")'
```

### `tetra` CLI

The `tetra` CLI is already available inside `tetragon` container.

To see events in compact format use the following command:

```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```

To filter events by the `xwing` pod use the following command:
```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --namespace default --pod xwing
```

These will produce the following events:
```bash
🚀 process default/xwing /bin/bash
🚀 process default/xwing /usr/bin/whoami
💥 exit    default/xwing /usr/bin/whoami 0
```

Here you can see the binary names along with its arguments, the pod info, and
return codes in a compact one-line view of the events.


It is also possible to explore events without entering the `tetragon` container, by [installing `tetra` CLI](/docs/getting-started/install-tetra-cli).

1. Pretty print `tetragon` JSON raw output:

   ```bash
   kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact
   ```

2. Pretty print `tetragon` JSON raw output and filter by `xwing` pod events:

   ```bash
   kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact --namespace default --pod xwing
   ```
