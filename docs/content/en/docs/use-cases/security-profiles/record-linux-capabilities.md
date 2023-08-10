---
title: "Record Linux Capabilities Usage"
weight: 2
icon: "overview"
description: "Record a capability profile of pods and containers"
---

When the kernel needs to perform a privileged operation on behalf of a process, it checks
the [Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) of the process
and issues a verdict to allow or deny the operation.

Tetragon is able to record these checks performed by the kernel. This can be used to answer
the following questions:

> What is the capabilities profile of pods or containters running in the cluster?

> What capabilities to add or remove when [configuring a security context for a pod or container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)?

## Kubernetes Environments

First, verify that your k8s environment is set up and that all pods are up and running, and deploy the demo application:

```shell-session
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/v1.11/examples/minikube/http-sw-app.yaml
```

It might take several seconds until all pods are Running:

```shell-session
kubectl get pods -A
```

The output should be similar to:
```
NAMESPACE            NAME                                         READY   STATUS    RESTARTS   AGE
default              deathstar-54bb8475cc-6c6lc                   1/1     Running   0          2m54s
default              deathstar-54bb8475cc-zmfkr                   1/1     Running   0          2m54s
default              tiefighter                                   1/1     Running   0          2m54s
default              xwing                                        1/1     Running   0          2m54s
kube-system          tetragon-sdwv6                               2/2     Running   0          27m
```

### Monitor Capability Checks

We use the [creds-capability-usage](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/creds-capability-usage.yaml) tracing policy which generates [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events.

{{< note >}}
Tracing policies as the one used here, may emit a high number of events.

To reduce events, the [creds-capability-usage](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/creds-capability-usage.yaml) rate limits events to 1 minute. More details about rate-limiting can be found in the [tracing policy documentation]({{< ref "docs/concepts/tracing-policy#actions-filter" >}}).
{{< /note >}}

Apply the [creds-capability-usage](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/creds-capability-usage.yaml) policy:
```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/creds-capability-usage.yaml
```

Start monitoring for events with `tetra` cli, but match only events of `xwing` pod:
```shell-session
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents --namespaces default --pods xwing
```

In another terminal, kubectl exec into the xwing pod:
```shell-session
kubectl exec -it xwing -- /bin/bash
```

As an example execute [dmesg](https://man7.org/linux/man-pages/man1/dmesg.1.html) to print the kernel ring buffer. This requires the special capability `CAP_SYSLOG`:

```shell-session
dmesg
```

The output should be similar to:
```
dmesg: klogctl: Operation not permitted
```

The `tetra` cli will generate the following [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events:

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjEyODQyNzgzMzUwNjg0OjczODYw",
      "pid": 73860,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/dmesg",
      "flags": "execve rootcwd clone",
      "start_time": "2023-07-06T10:13:33.834390020Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://cfb961400ff25811d22d139a10f6a62efef53c2ecc11af47bc911a7f9a2ac1f7",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-07-06T08:07:30Z",
          "pid": 171
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "cfb961400ff25811d22d139a10f6a62",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjEyODQyMTI3MTIwOTcyOjczODUw",
      "refcnt": 1,
      "ns": {
        "uts": {
          "inum": 4026534655
        },
        "ipc": {
          "inum": 4026534656
        },
        "mnt": {
          "inum": 4026534731
        },
        "pid": {
          "inum": 4026534732
        },
        "pid_for_children": {
          "inum": 4026534732
        },
        "net": {
          "inum": 4026534512
        },
        "time": {
          "inum": 4026531834,
          "is_host": true
        },
        "time_for_children": {
          "inum": 4026531834,
          "is_host": true
        },
        "cgroup": {
          "inum": 4026534733
        },
        "user": {
          "inum": 4026531837,
          "is_host": true
        }
      },
      "tid": 73860
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjEyODQyMTI3MTIwOTcyOjczODUw",
      "pid": 73850,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2023-07-06T10:13:33.178160018Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://cfb961400ff25811d22d139a10f6a62efef53c2ecc11af47bc911a7f9a2ac1f7",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-07-06T08:07:30Z",
          "pid": 165
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "cfb961400ff25811d22d139a10f6a62",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjEyODQyMDgxNTA3MzUzOjczODQx",
      "refcnt": 2,
      "tid": 73850
    },
    "function_name": "cap_capable",
    "args": [
      {
        "user_ns_arg": {
          "level": 0,
          "uid": 0,
          "gid": 0,
          "ns": {
            "inum": 4026531837,
            "is_host": true
          }
        }
      },
      {
        "capability_arg": {
          "value": 34,
          "name": "CAP_SYSLOG"
        }
      }
    ],
    "return": {
      "int_arg": -1
    },
    "action": "KPROBE_ACTION_POST"
  },
  "node_name": "kind-control-plane",
  "time": "2023-07-06T10:13:33.834882128Z"
}
```

In addition to the Kubernetes Identity and process metadata from exec events, [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events contain the arguments of the observed system call. In the above case they are:

* `function_name`: that is the `cap_capable` kernel function.

* `user_ns_arg`: is the [user namespace]({{< ref "/docs/reference/grpc-api#usernamespace" >}}) where the capability is required.

   * `level`: is the nested level of the user namespace. Here it is zero which indicates the initial user namespace.
   * `uid`: is the user ID of the owner of the user namespace.
   * `gid`: is the group ID of the owner of the user namespace.
   * [`ns`]({{< ref "/docs/reference/grpc-api#namespace" >}}): details the information about the namespace. `is_host` indicates that the target user namespace where the capability is required is the host namespace.

* `capability_arg`: is the [capability]({{< ref "/docs/reference/grpc-api#kprobecapability" >}}) required to perform the operation. In this example reading the kernel ring buffer.

   * `value`: is the integer number of the required capability.
   * `name`: is the name of the required capability. Here it is the `CAP_SYSLOG`.

* `return`: indicates via the `int_arg` if the capability check succeeded or failed. `0` means it succeeded and the access was granted while `-1` means it failed and the operation was denied.

To disable the [creds-capability-usage](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/creds-capability-usage.yaml) run:

```shell-session
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/creds-capability-usage.yaml
```
