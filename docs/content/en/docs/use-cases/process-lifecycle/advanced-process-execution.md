---
title: "Advanced Process execution"
weight: 2
icon: "overview"
description: "Advanced Process Execution monitoring using Tracing Policies"
---

## Monitor ELF or Flat binaries execution

Advanced process execution can be performed by using [Tracing Policies](/docs/concepts/tracing-policy) to monitor
the [execve system call](https://man7.org/linux/man-pages/man2/execve.2.html) path.

If we want to monitor execution of Executable and Linkable Format (ELF) or flat binaries
before they are actually executed. Then the [process-exec-elf-begin](https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/process-exec/process-exec-elf-begin.yaml) tracing policy is a good first choice.

{{< note >}}
The [process-exec-elf-begin](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-exec/process-exec-elf-begin.yaml) tracing policy, will not report the
different binary format handlers or scripts being executed, but will report
the final ELF or flat binary, like the shebang handler.

To report those another tracing policy can be used.
{{</ note >}}

Before going forward, verify that all pods are up and running, ensure you
deploy our Demo Application to explore the Security Observability Events:

```bash
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/v1.11/examples/minikube/http-sw-app.yaml
```

It might take several seconds for some pods until they satisfy all the dependencies:

```shell-session
kubectl get pods -A
```
The output should be similar to:
```text
NAMESPACE            NAME                                         READY   STATUS    RESTARTS   AGE
default              deathstar-54bb8475cc-6c6lc                   1/1     Running   0          2m54s
default              deathstar-54bb8475cc-zmfkr                   1/1     Running   0          2m54s
default              tiefighter                                   1/1     Running   0          2m54s
default              xwing                                        1/1     Running   0          2m54s
kube-system          tetragon-sdwv6                               2/2     Running   0          27m
```

Let's apply the [process-exec-elf-begin](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-exec/process-exec-elf-begin.yaml) Tracing Policy.

```bash
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-exec/process-exec-elf-begin.yaml
```

Then start monitoring events with the `tetra` CLI:
```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents
```

In another terminal, `kubectl exec` into the xwing Pod:

```bash
kubectl exec -it xwing -- /bin/bash
```

And execute some commands:

```bash
id
```

The `tetra` CLI will generate the following [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events:

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE2NjY0MDI4MTA4MzcxOjM2NDk5",
      "pid": 36499,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve",
      "start_time": "2023-08-02T11:58:53.618461573Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://775beeb1a25a95e10dc149d6eb166bf45dd5e6039e8af3b64e8fb4d29669f349",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-08-02T07:24:54Z",
          "pid": 13
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "775beeb1a25a95e10dc149d6eb166bf",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE2NjYyNzg3ODI1MTQ4OjM2NDkz",
      "refcnt": 1,
      "tid": 36499
    },
      "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE2NjYyNzg3ODI1MTQ4OjM2NDkz",
      "pid": 36493,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2023-08-02T11:58:52.378178852Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://775beeb1a25a95e10dc149d6eb166bf45dd5e6039e8af3b64e8fb4d29669f349",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-08-02T07:24:54Z",
          "pid": 13
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "775beeb1a25a95e10dc149d6eb166bf",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE2NjYyNzE2OTU0MjgzOjM2NDg0",
      "tid": 36493
    },
    "function_name": "security_bprm_creds_from_file",
    "args": [
      {
        "file_arg": {
          "path": "/bin/busybox"
        }
      }
    ],
    "action": "KPROBE_ACTION_POST"
  },
  "node_name": "kind-control-plane",
  "time": "2023-08-02T11:58:53.624096751Z"
}
```

In addition to the Kubernetes Identity and process metadata,
[ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}})
events contain the binary being executed. In the above case they are:

- `function_name`: where we are hooking into the kernel to read the binary that is being executed.
- `file_arg`: that includes the `path` being executed, and here it is `/bin/busybox` that is the real
   binary being executed, since on the `xwing` pod the container is running [busybox](https://busybox.net/).
   The binary `/usr/bin/id -> /bin/busybox` points to busybox.


To disable the [process-exec-elf-being](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-exec/process-exec-elf-begin.yaml) Tracing Policy run:

```bash
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-exec/process-exec-elf-begin.yaml
```
