---
title: "Use case: file access"
weight: 1
icon: "overview"
description: "Monitor file access using kprobe hooks"
---

The first use case is file access, which can be observed with the Tetragon
`process_kprobe` JSON events. By using kprobe hook points, these events are
able to observe arbitrary kernel calls and file descriptors in the Linux
kernel, giving you the ability to monitor every file a process opens, reads,
writes, and closes throughout its lifecycle.

In this example, we can monitor if a process inside a Kubernetes workload performs
an read or write in the `/etc/` directory. The policy may further
specify additional directories or specific files if needed.

As a first step, let's apply the following `TracingPolicy` (```file_monitoring_filtered.yaml``` contains an example for filtering read/write accesses):

```bash
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/file_monitoring.yaml
```

This tracing policy contains three kprobe hooks. The first kprobe hook monitors different ways to do I/O to files. These include:

- Using `read`/`write` family system calls. These include: `read`, `readv`, `pread64`, `preadv`, `preadv2`, `write`, `writev`, `pwrite64`, `pwritev`, and `pwritev2` system calls.
- Optimized ways to copy files inside kernel. These include: `copy_file_range`, `sendfile`, and `splice` system calls.- Asynchronous ways to do I/O. These include [`io_uring`](https://man.archlinux.org/man/io_uring.7.en) and [`aio`](https://man7.org/linux/man-pages/man7/aio.7.html).
- `fallocate` system call and its variants.
The second kprobe hook tracks `mmap` calls (including read/write flags) to files that we monitor. The third hook monitors `truncate` system call and its variants.

As a second step, let's start monitoring the events from the `xwing` pod:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact --namespace default --pod xwing
```

In another terminal, `kubectl exec` into the `xwing` pod:

```bash
kubectl exec -it xwing -- /bin/bash
```

and edit the `/etc/passwd` file:

```bash
vi /etc/passwd
```

If you observe, the output in the first terminal should be:

```bash
🚀 process default/xwing /bin/bash
📚 read    default/xwing /bin/bash /etc/passwd
📚 read    default/xwing /bin/bash /etc/passwd
💥 exit    default/xwing /bin/bash  127
🚀 process default/xwing /usr/bin/vi /etc/passwd
📚 read    default/xwing /usr/bin/vi /etc/passwd
📚 read    default/xwing /usr/bin/vi /etc/passwd
📝 write   default/xwing /usr/bin/vi /etc/passwd
📝 write   default/xwing /usr/bin/vi /etc/passwd
📝 trunc   default/xwing /usr/bin/vi /etc/passwd
💥 exit    default/xwing /usr/bin/vi /etc/passwd 0
```

Note, that read and writes are only generated for `/etc/` files because of eBPF in kernel
filtering. The default CRD additionally filters events associated with the
pod init process to filter init noise from pod start.

Similarly to the previous example, reviewing the JSON events provides
additional data. An example `process_kprobe` event observing a write can be:

### Process Kprobe Event

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjMyMDY2OTEyNDkyMTA4MToyMDk3ODM=",
      "pid": 209783,
      "uid": 0,
      "cwd": "/",
      "binary": "/usr/bin/vi",
      "arguments": "/etc/passwd",
      "flags": "execve rootcwd clone",
      "start_time": "2023-06-26T11:23:43.774969054Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1f1d1ed09d56f04c17857cc5154f11d22d738b04b28941accd08569183caa4b5",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-06-26T11:11:01Z",
          "pid": 37
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "1f1d1ed09d56f04c17857cc5154f11d",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjMyMDY2MDM3OTEzODY1MzoyMDk3NTE=",
      "refcnt": 1,
      "tid": 209783
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjMyMDY2MDM3OTEzODY1MzoyMDk3NTE=",
      "pid": 209751,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/bash",
      "flags": "execve rootcwd clone",
      "start_time": "2023-06-26T11:23:35.029187062Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "xwing",
        "container": {
          "id": "containerd://1f1d1ed09d56f04c17857cc5154f11d22d738b04b28941accd08569183caa4b5",
          "name": "spaceship",
          "image": {
            "id": "docker.io/tgraf/netperf@sha256:8e86f744bfea165fd4ce68caa05abc96500f40130b857773186401926af7e9e6",
            "name": "docker.io/tgraf/netperf:latest"
          },
          "start_time": "2023-06-26T11:11:01Z",
          "pid": 28
        },
        "pod_labels": {
          "app.kubernetes.io/name": "xwing",
          "class": "xwing",
          "org": "alliance"
        }
      },
      "docker": "1f1d1ed09d56f04c17857cc5154f11d",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjMyMDY2MDM0NTk5MzM2NToyMDk3NDE=",
      "refcnt": 2,
      "tid": 209751
    },
    "function_name": "security_file_permission",
    "args": [
      {
        "file_arg": {
          "path": "/etc/passwd"
        }
      },
      {
        "int_arg": 2
      }
    ],
    "return": {
      "int_arg": 0
    },
    "action": "KPROBE_ACTION_POST"
  },
  "node_name": "kind-control-plane",
  "time": "2023-06-26T11:23:49.019160599Z"
}
```

In addition to the Kubernetes Identity
and process metadata from exec events, `process_kprobe` events contain
the arguments of the observed system call. In the above case they are

- `file_arg.path`: the observed file path
- `int_arg`: is the type of the operation (2 for a write and 4 for a read)
- `return.int_arg`: is 0 if the operation is allowed

To disable the `TracingPolicy` run:

```bash
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/file_monitoring.yaml
```
