---
title: "Filename access"
weight: 2
icon: "overview"
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

The first is read and write accesses, which the most common way that files are accessed by
applications.  Applications can perform this type of accesses with a variety of different system
calls:  `read` and `write`, optimized system calls such as `copy_file_range` and `sendfile`, as well
as asynchronous I/O system call families such as the ones provided by `aio` and `io_uring`. Instead
of monitoring every system call, we opt to hook into the `security_file_permission` hook, which is a
common execution point for all the above system calls.

Applications can also access files by mapping them directly into their virtual address space. Since
it is difficult to caught the accesses themselves in this case, our policy will instead monitor the
point when the files are mapped into the application's virtual memory. To do so, we use the
`security_mmap_file` hook.

Lastly, there is a family of system calls (e.g,. `truncate`) that allow to indirectly modify the
contents of the file by changing its size. To catch these types of accesses we will hook into
`security_path_truncate`.

## Filtering

Using the hooks above, you can monitor all accesses in the system. This will create a large number
of events,  however, and it is frequently the case that you are only interested in a specific subset
those events. It is possible to filter the events after their generation, but this induces
unnecessary overhead. Tetragon, using BPF, allows filtering these events directly in the kernel.

For example, the following snippet shows how you can limit the events from the
`security_file_permission` hook only for the `/etc/shadow` file. For this, you need to specify the
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

In this example, we monitor if a process inside a Kubernetes workload performs an read or write in
the `/etc/` directory. The policy may be extended with additional directories or specific files if
needed.

As a first step, we apply the following policy that uses the three hooks mentioned previously as
well as appropriate filtering:

```bash
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/filename_monitoring.yaml
```

Next, you can start monitoring the events from the `xwing` pod:

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

Note, that read and writes are only generated for `/etc/` files based on BPF in-kernel filtering
specified in the policy. The default CRD additionally filters events associated with the pod init
process to filter init noise from pod start.

Similarly to the previous example, reviewing the JSON events provides additional data. An example
`process_kprobe` event observing a write can be:

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
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/filename_monitoring.yaml
```

Another example of a [similar
policy](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/filename_monitoring_filtered.yaml)
can be found in our examples folder.

##  Limitations

Note that this policy has certain limitations because it matches on the filename that the
application uses to accesses. If an application accesses the same file via a hard link or a
different bind mount, no event will be generated.
