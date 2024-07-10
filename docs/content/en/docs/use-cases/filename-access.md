---
title: "Filename access"
weight: 2
description: "Monitor filename access using kprobe hooks"
---

This page shows how you can create a tracing policy to monitor filename access. For general
information about tracing policies, see the [tracing policy page]({{< ref
"/docs/concepts/tracing-policy/hooks" >}}).

There are two aspects of the tracing policy: (i) what hooks you can use to monitor specific types of
access, and (ii) how you can filter at the kernel level for only specific events. 

## Hooks

There are different ways applications can access and modify files, and for this tracing policy we
focus in three different types.

The first is read and write accesses, which is the most common way that applications access files.  Applications can perform this type of accesses with a variety of different system
calls:  `read` and `write`, optimized system calls such as `copy_file_range` and `sendfile`, as well
as asynchronous I/O system call families such as the ones provided by `aio` and `io_uring`. Instead
of monitoring every system call, we opt to hook into the `security_file_permission` hook, which is a
common execution point for all the above system calls.

Applications can also access files by mapping them directly into their virtual address space. Since
it is difficult to catch the accesses themselves in this case, our policy will instead monitor the
point when the files are mapped into the application's virtual memory. To do so, we use the
`security_mmap_file` hook.

Lastly, there is a family of system calls (e.g,. `truncate`) that allow to indirectly modify the
contents of the file by changing its size. To catch these types of access we will hook into
`security_path_truncate`.

## Filtering

Using the hooks above, you can monitor all accesses in the system. However, this will create a large number
of events, and it is frequently the case that you are only interested in a specific subset
those events. It is possible to filter the events after their generation, but this induces
unnecessary overhead. Tetragon, using BPF, allows filtering these events directly in the kernel.

For example, the following snippet shows how you can limit the events from the
`security_file_permission` hook only for the `/etc/passwd` file. For this, you need to specify the
arguments of the function that you hooking into, as well as their type.

```yaml
  - call: "security_file_permission"
    syscall: false
    args:
    - index: 0
      type: "file" # (struct file *) used for getting the path
    - index: 1
      type: "int" # 0x04 is MAY_READ, 0x02 is MAY_WRITE
    selectors:
    - matchArgs:      
      - index: 0
        operator: "Equal"
        values:
        - "/etc/passwd" # filter by filename (/etc/passwd)
      - index: 1
        operator: "Equal"
        values:
        - "2" # filter by type of access (MAY_WRITE)
```

The previous example uses the `Equal` operator. Similarly, you can use the `Prefix` operator to
filter events based on the prefix of a filename.

## Examples

In this example, we monitor if a process inside a Kubernetes workload performs a read or write in
the `/etc/` directory. The policy may be extended with additional directories or specific files if
needed.

As a first step, we apply the following policy that uses the three hooks mentioned previously as
well as appropriate filtering:

```bash
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/filename_monitoring.yaml
```

Next, we deploy a `file-access` Pod with an interactive bash session:

```bash
kubectl run --rm -it file-access -n default --image=busybox --restart=Never
```

In another terminal, you can start monitoring the events from the `file-access` Pod:

```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --namespace default --pod file-access
```

In the interactive bash session, edit the `/etc/passwd` file:

```bash
vi /etc/passwd
```

If you observe, the output in the second terminal should be:

```bash
🚀 process default/file-access /bin/sh
🚀 process default/file-access /bin/vi /etc/passwd
📚 read    default/file-access /bin/vi /etc/passwd
📚 read    default/file-access /bin/vi /etc/passwd
📚 read    default/file-access /bin/vi /etc/passwd
📝 write   default/file-access /bin/vi /etc/passwd
📝 truncate default/file-access /bin/vi /etc/passwd
💥 exit    default/file-access /bin/vi /etc/passwd 0
```

Note that read and writes are only generated for `/etc/` files based on BPF in-kernel filtering
specified in the policy. The default CRD additionally filters events associated with the pod init
process to filter init noise from pod start.

Similarly to the previous example, reviewing the JSON events provides additional data. An example
`process_kprobe` event observing a write can be:

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "dGV0cmFnb24tZGV2LWNvbnRyb2wtcGxhbmU6MTY4MTc3MDUwMTI1NDI6NjQ3NDY=",
      "pid": 64746,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/vi",
      "arguments": "/etc/passwd",
      "flags": "execve rootcwd clone",
      "start_time": "2024-04-14T02:18:02.240856427Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "file-access",
        "container": {
          "id": "containerd://6b742e38ee3a212239e6d48b2954435a407af44b9a354bdf540db22f460ab40e",
          "name": "file-access",
          "image": {
            "id": "docker.io/library/busybox@sha256:c3839dd800b9eb7603340509769c43e146a74c63dca3045a8e7dc8ee07e53966",
            "name": "docker.io/library/busybox:latest"
          },
          "start_time": "2024-04-14T02:17:46Z",
          "pid": 12
        },
        "pod_labels": {
          "run": "file-access"
        },
        "workload": "file-access",
        "workload_kind": "Pod"
      },
      "docker": "6b742e38ee3a212239e6d48b2954435",
      "parent_exec_id": "dGV0cmFnb24tZGV2LWNvbnRyb2wtcGxhbmU6MTY4MDE3MDQ3OTQyOTg6NjQ2MTU=",
      "refcnt": 1,
      "tid": 64746
    },
    "parent": {
      "exec_id": "dGV0cmFnb24tZGV2LWNvbnRyb2wtcGxhbmU6MTY4MDE3MDQ3OTQyOTg6NjQ2MTU=",
      "pid": 64615,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/sh",
      "flags": "execve rootcwd clone",
      "start_time": "2024-04-14T02:17:46.240638141Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "default",
        "name": "file-access",
        "container": {
          "id": "containerd://6b742e38ee3a212239e6d48b2954435a407af44b9a354bdf540db22f460ab40e",
          "name": "file-access",
          "image": {
            "id": "docker.io/library/busybox@sha256:c3839dd800b9eb7603340509769c43e146a74c63dca3045a8e7dc8ee07e53966",
            "name": "docker.io/library/busybox:latest"
          },
          "start_time": "2024-04-14T02:17:46Z",
          "pid": 1
        },
        "pod_labels": {
          "run": "file-access"
        },
        "workload": "file-access",
        "workload_kind": "Pod"
      },
      "docker": "6b742e38ee3a212239e6d48b2954435",
      "parent_exec_id": "dGV0cmFnb24tZGV2LWNvbnRyb2wtcGxhbmU6MTY3OTgyOTA2MDc3NTc6NjQ1NjQ=",
      "tid": 64615
    },
    "function_name": "security_file_permission",
    "args": [
      {
        "file_arg": {
          "path": "/etc/passwd",
          "permission": "-rw-r--r--"
        }
      },
      {
        "int_arg": 2
      }
    ],
    "return": {
      "int_arg": 0
    },
    "action": "KPROBE_ACTION_POST",
    "policy_name": "file-monitoring",
    "return_action": "KPROBE_ACTION_POST"
  },
  "node_name": "tetragon-dev-control-plane",
  "time": "2024-04-14T02:18:14.376304204Z"
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
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/filename_monitoring.yaml
```

To delete the `file-access` Pod from the interactive bash session, type:

```bash
exit
```

Another example of a [similar
policy](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/filename_monitoring_filtered.yaml)
can be found in our examples folder.

##  Limitations

Note that this policy has certain limitations because it matches on the filename that the
application uses to access. If an application accesses the same file via a hard link or a
different bind mount, no event will be generated.
