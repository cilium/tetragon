---
title: "Monitor Process Credentials changes at the Kernel layer"
weight: 2
icon: "overview"
description: "Monitor Process Credentials changes at the kernel layer"
---

Monitoring Process Credentials changes at the kernel layer is also possible.
This allows to capture the new [`process_credentials`]({{< ref "/docs/reference/grpc-api#processcredentials" >}}) that should be applied.

This [process-creds-installed](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process-creds-installed.yaml) tracing policy can be used to answer the following questions:

> Which process or container is trying to change its own UIDs/GIDs in the cluster?

> Which process or container is trying to change its own capabilities in the cluster?

> In which [user namespace](https://man7.org/linux/man-pages/man7/user_namespaces.7.html) the credentials are being changed?

> How to monitor [`process_credentials`]({{< ref "/docs/reference/grpc-api#processcredentials" >}}) changes?

## Advantages and disadvantages of kernel layer monitoring compared to the system call layer

The main advantages of monitoring at the kernel layer compared to the [system call layer](/docs/use-cases/linux-process-credentials/syscalls-monitoring):

* Not vulnerable to user space arguments tampering.

* Ability to display the full new credentials to be applied.

* It is more reliable since it has full context on where and how the new credentials should be applied including the user namespace.

* A catch all layer for all system calls, and every normal kernel path that manipulate credentials.

* One potential disadvantage is that this approach may generate a lot of events, so appropriate filtering must be applied to reduce the noise.

## Kubernetes Environments

First, verify that your k8s environment is all setup and that all pods are up and running, and  deploy the Demo Application:

```shell-session
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/v1.11/examples/minikube/http-sw-app.yaml
```

It might take several seconds until all pods are Running:

```shell-session
kubectl get pods -A
NAMESPACE            NAME                                         READY   STATUS    RESTARTS   AGE
default              deathstar-54bb8475cc-6c6lc                   1/1     Running   0          2m54s
default              deathstar-54bb8475cc-zmfkr                   1/1     Running   0          2m54s
default              tiefighter                                   1/1     Running   0          2m54s
default              xwing                                        1/1     Running   0          2m54s
kube-system          tetragon-sdwv6                               2/2     Running   0          27m
```

### Monitor Process Credentials installation

We use the [process-creds-installed](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process-creds-installed.yaml) Tracing Policy that hooks the kernel layer when credentials are being installed.

So let's apply the [process-creds-installed](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process-creds-installed.yaml) Tracing Policy.

```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process-creds-installed.yaml
```

Then we start monitoring for events with `tetra` cli:
```shell-session
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents
```

In another terminal, inside a pod and as a non root user we will execute a setuid binary (suid):

```shell-session
/tmp/su -
```

The `tetra` cli will generate the following [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events:

```json
{
 "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE0MDczMDQyODk3MTc6MjIzODY=",
      "pid": 22386,
      "uid": 11,
      "cwd": "/",
      "binary": "/tmp/su",
      "arguments": "-",
      "flags": "execve rootcwd clone",
      "start_time": "2023-07-25T12:04:59.359333454Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://2e58c8357465961fd96f758e87d0269dfb5f97c536847485de9d7ec62be34a64",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-07-25T11:44:48Z",
          "pid": 43
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "2e58c8357465961fd96f758e87d0269",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjEzOTU0MDY5OTA1ODc6MjIzNTI=",
      "refcnt": 1,
      "tid": 22386
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjEzOTU0MDY5OTA1ODc6MjIzNTI=",
      "pid": 22352,
      "uid": 11,
      "cwd": "/",
      "binary": "/bin/sh",
      "flags": "execve rootcwd",
      "start_time": "2023-07-25T12:04:47.462035587Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
                "name": "xwing",
        "container": {
          "id": "containerd://2e58c8357465961fd96f758e87d0269dfb5f97c536847485de9d7ec62be34a64",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-07-25T11:44:48Z",
          "pid": 41
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "2e58c8357465961fd96f758e87d0269",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjEzOTU0MDQ3NzY5NzI6MjIzNTI=",
      "refcnt": 2,
      "tid": 22352
    },
    "function_name": "commit_creds",
    "args": [
      {
        "process_credentials_arg": {
          "uid": 0,
          "gid": 0,
          "euid": 0,
          "egid": 0,
          "suid": 0,
          "sgid": 0,
          "fsuid": 0,
          "fsgid": 0,
          "caps": {
            "permitted": [
              "CAP_CHOWN",
              "DAC_OVERRIDE",
              "CAP_FOWNER",
              "CAP_FSETID",
              "CAP_KILL",
              "CAP_SETGID",
              "CAP_SETUID",
              "CAP_SETPCAP",
              "CAP_NET_BIND_SERVICE",
              "CAP_NET_RAW",
              "CAP_SYS_CHROOT",
              "CAP_MKNOD",
              "CAP_AUDIT_WRITE",
              "CAP_SETFCAP"
            ],
            "effective": [
              "CAP_CHOWN",
              "DAC_OVERRIDE",
              "CAP_FOWNER",
              "CAP_FSETID",
              "CAP_KILL",
              "CAP_SETGID",
              "CAP_SETUID",
              "CAP_SETPCAP",
              "CAP_NET_BIND_SERVICE",
              "CAP_NET_RAW",
              "CAP_SYS_CHROOT",
              "CAP_MKNOD",
              "CAP_AUDIT_WRITE",
              "CAP_SETFCAP"
            ]
          },
          "user_ns": {
            "level": 0,
            "uid": 0,
            "gid": 0,
            "ns": {
              "inum": 4026531837,
              "is_host": true
            }
          }
        }
      }
    ],
    "action": "KPROBE_ACTION_POST"
  },
  "node_name": "kind-control-plane",
  "time": "2023-07-25T12:05:01.410834172Z"
}
```

In addition to the Kubernetes Identity and process metadata from exec events, [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events contain the arguments of the observed system call. In the above case they are:

- `function_name`: the kernel `commit_creds()` function to install new credentials.
- `process_credentials_arg`: the new [`process_credentials`]({{< ref "/docs/reference/grpc-api#processcredentials" >}}) to be installed
   on the current process. It includes the UIDs/GIDs, the capabilities and the target user namespace.

Here we can clearly see that the suid binary is being executed by a user ID `11` in order to elevate its privileges to user ID `0` including capabilities.

To disable the [process-creds-installed Tracing Policy](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process-creds-installed.yaml) run:

```shell-session
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/process-credentials/process-creds-installed.yaml
```
