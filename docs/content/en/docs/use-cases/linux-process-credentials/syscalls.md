---
title: "Credentials change system calls"
weight: 1
icon: "overview"
description: "Monitor credentials change system calls"
---

Tetragon can hook at the system calls that directly manipulate the credentials.
This allows us to determine which process is trying to change its credentials
and the new credentials that could be applied by the kernel.

This answers the questions:

> Which process or container is trying to change its UIDs/GIDs in my cluster?

> Which process or container is trying to change its capabilities in my
> cluster?

Before going forward, verify that all pods are up and running, ensure you
deploy our Demo Application to explore the Security Observability Events:

```bash
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/v1.11/examples/minikube/http-sw-app.yaml
```

It might take several seconds for some pods until they satisfy all the dependencies:

```bash
kubectl get pods -A
NAMESPACE            NAME                                         READY   STATUS    RESTARTS   AGE
default              deathstar-54bb8475cc-6c6lc                   1/1     Running   0          2m54s
default              deathstar-54bb8475cc-zmfkr                   1/1     Running   0          2m54s
default              tiefighter                                   1/1     Running   0          2m54s
default              xwing                                        1/1     Running   0          2m54s
kube-system          tetragon-sdwv6                               2/2     Running   0          27m
```

## Monitor UIDs/GIDs credential changes

We use the
[process.credentials.changes.at.syscalls](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process.credentials.changes.at.syscalls.yaml)
Tracing Policy that hooks the
[`setuid`](https://man7.org/linux/man-pages/man2/setuid.2.html) system calls
family:

- `setuid`
- `setgid`
- `setfsuid`
- `setfsgid`
- `setreuid`
- `setregid`
- `setresuid`
- `setresgid`

Let's apply the [process.credentials.changes.at.syscalls](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process.credentials.changes.at.syscalls.yaml) Tracing Policy.

```bash
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process.credentials.changes.at.syscalls.yaml
```

Then start monitoring events with the `tetra` CLI:
```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents
```

In another terminal, `kubectl exec` into the xwing Pod:

```bash
kubectl exec -it xwing -- /bin/bash
```

And execute [su](https://en.wikipedia.org/wiki/Su_(Unix)) as this will call the
related `setuid` system calls:

```bash
su root
```

The `tetra` CLI will generate the following [ProcessKprobe](https://tetragon.cilium.io/docs/reference/grpc-api/#processkprobe) events:

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQwNzk4ODc2MDI2NTk4OjEyNTc5OA==",
      "pid": 125798,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/su",
      "arguments": "root",
      "flags": "execve rootcwd clone",
      "start_time": "2023-07-05T19:14:30.918693157Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://55936e548de63f77ceb595d64966dd8e267b391ff0ef63b26c17eb8c2f6510be",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-07-05T18:45:16Z",
          "pid": 19
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "55936e548de63f77ceb595d64966dd8",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQwNzk1NjYyMDM3MzMyOjEyNTc5Mg==",
      "refcnt": 1,
      "tid": 125798
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQwNzk1NjYyMDM3MzMyOjEyNTc5Mg==",
      "pid": 125792,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2023-07-05T19:14:27.704703805Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://55936e548de63f77ceb595d64966dd8e267b391ff0ef63b26c17eb8c2f6510be",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-07-05T18:45:16Z",
          "pid": 13
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "55936e548de63f77ceb595d64966dd8",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQwNzk1NjE2MTU0NzA2OjEyNTc4Mw==",
      "refcnt": 2,
      "tid": 125792
    },
    "function_name": "__x64_sys_setgid",
    "args": [
      {
        "int_arg": 0
      }
    ],
    "action": "KPROBE_ACTION_POST"
  },
  "node_name": "kind-control-plane",
  "time": "2023-07-05T19:14:30.918977160Z"
}
{
  "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQwNzk4ODc2MDI2NTk4OjEyNTc5OA==",
      "pid": 125798,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/su",
      "arguments": "root",
      "flags": "execve rootcwd clone",
      "start_time": "2023-07-05T19:14:30.918693157Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://55936e548de63f77ceb595d64966dd8e267b391ff0ef63b26c17eb8c2f6510be",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-07-05T18:45:16Z",
          "pid": 19
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "55936e548de63f77ceb595d64966dd8",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQwNzk1NjYyMDM3MzMyOjEyNTc5Mg==",
      "refcnt": 1,
      "tid": 125798
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQwNzk1NjYyMDM3MzMyOjEyNTc5Mg==",
      "pid": 125792,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2023-07-05T19:14:27.704703805Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://55936e548de63f77ceb595d64966dd8e267b391ff0ef63b26c17eb8c2f6510be",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-07-05T18:45:16Z",
          "pid": 13
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "55936e548de63f77ceb595d64966dd8",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQwNzk1NjE2MTU0NzA2OjEyNTc4Mw==",
      "refcnt": 2,
      "tid": 125792
    },
    "function_name": "__x64_sys_setuid",
    "args": [
      {
        "int_arg": 0
      }
    ],
    "action": "KPROBE_ACTION_POST"
  },
  "node_name": "kind-control-plane",
  "time": "2023-07-05T19:14:30.918990583Z"
}
```

In addition to the Kubernetes Identity and process metadata from exec events,
[ProcessKprobe](https://tetragon.cilium.io/docs/reference/grpc-api/#processkprobe)
events contain the arguments of the observed system call. In the above case
they are:

- `function_name`: the system call, `__x64_sys_setuid` or
  `__x64_sys_setgid`
- `int_arg`: the `uid` or `gid` to use, in our case it's 0 which corresponds to
  the root user.


To disable the [process.credentials.changes.at.syscalls](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process.credentials.changes.at.syscalls.yaml) Tracing Policy run:

```bash
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process.credentials.changes.at.syscalls.yaml
```
