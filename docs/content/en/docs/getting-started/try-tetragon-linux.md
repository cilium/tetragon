---
title: "Try Tetragon on Linux"
weight: 1
description: "Discover and experiment with Tetragon on your local Linux host"
---

{{< caution >}}
This guide is not a tutorial on how to deploy Tetragon standalone (i.e. without
Kubernetes), you can see the [container deployment](/docs/getting-started/deployment/container)
and [package deployment](/docs/getting-started/deployment/package) guides for
that. This is just a walkthrough to try and experiment Tetragon for the first
time.
{{< /caution >}}

{{< note >}}
This guide has been tested on Ubuntu 22.04 and 22.10 with respectively kernel
`5.15.0` and `5.19.0` on amd64 and arm64 but
[any recent distribution](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere)
shipping with a relatively recent kernel should work.

Note that you cannot run Tetragon using Docker Desktop on macOS because of a
limitation of the Docker Desktop Linux virtual machine. Learn more about this issue
and how to run Tetragon on a Mac computer in [this section of the FAQ page](/docs/faq/#can-i-run-tetragon-on-mac-computers).
{{< /note >}}

## Start Tetragon

The easiest way to start experimenting with Tetragon is to run it via Docker
using the released container images. If you prefer running directly the
binaries without Docker, please refer to the
[development setup](/docs/contribution-guide/development-setup) to see how to
build the binaries.

```shell
docker run --name tetragon-container --rm --pull always \
    --pid=host --cgroupns=host --privileged             \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf    \
    quay.io/cilium/tetragon-ci:latest
```

Let's break down the previous command:
- `--name tetragon-container` names our container so that we can refer to it
  later via a simple name.
- `--rm` will make Docker delete the container once it exists.
- `--pull always` will force Docker to download the latest existing image
  corresponding to the `latest` mutable tag.
- `--pid=host` is needed to read the procfs for gathering context on processes
  started before Tetragon.
- `--cgroupns=host` is needed to detect container feature.
- `--privileged` is needed for Tetragon to load its BPF programs.
- `-v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf` mounts the BTF file inside
  the Tetragon container filesystem. Tetragon needs a BTF file corresponding to
  your kernel version to load its BPF programs.
- `quay.io/cilium/tetragon-ci:latest` is the latest version of Tetragon built
  from the main branch.

## Observe Tetragon base events

With this default configuration, Tetragon already loaded its base sensors to
perform [process lifecycle observability](/docs/tetragon-events/process-lifecycle/).

To quickly see the events, you can use the `tetra` CLI already shipped in the
Tetragon container that was just started, it will connect to the Tetragon gRPC
server listening on `localhost:54321`. In another terminal, type the following
command:

```shell
docker exec tetragon-container tetra getevents -o compact
```

In a different terminal, you can start a shell like `sh` and start executing
programs. Here, the commands executed in the shell where `ls`, `uname -a`,
`whoami`, and `exit`, the output should be similar to this:

```
🚀 process  /usr/bin/sh
🚀 process  /usr/bin/ls
💥 exit     /usr/bin/ls  0
🚀 process  /usr/bin/uname -a
💥 exit     /usr/bin/uname -a 0
🚀 process  /usr/bin/whoami
💥 exit     /usr/bin/whoami  0
💥 exit     /usr/bin/sh  0
```

You can see the start of `sh` first, then the execution of the multiple
programs, `ls`, `uname` and `whoami`, and finally the exit of `sh`.

{{< note >}}
Since Tetragon monitors all processes on the host, you may observe events
unrelated to what was typed in the shell session. Indeed, Tetragon is
monitoring every process start and exit in your environment.
{{< /note >}}

## Write a TracingPolicy to extend Tetragon events

Tetragon by default observes only process lifecycles. More advanced use-cases,
require configuring Tetragon via TracingPolicies. A TracingPolicy is a
user-configurable Kubernetes custom resource (CR) that allows users to access
additional functionality, such as tracing arbitrary events in the kernel and,
optionally, define actions to take on a match. These actions can be, for
example, used to implement enforcement.

{{< note >}}
For more details about TracingPolicies and how to write them, refer to the
[TracingPolicy reference](/docs/reference/tracing-policy).
{{< /note >}}

### Observability with TracingPolicy

Let's start with a simple policy:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "cat-open"
spec:
  kprobes:
  - call: "sys_openat"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "string"
    - index: 2
      type: "int"
    selectors:
    - matchBinaries:
      - operator: In
        values:
        - "/usr/bin/cat"
```

Copy this policy in a file named `tracing_policy.yaml` in your current working
directory and restart Tetragon with the following command:

```shell
docker run --name tetragon-container --rm --pull always \
    --pid=host --cgroupns=host --privileged             \
    -v $PWD/tracing_policy.yaml:/tracing_policy.yaml    \
    -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf    \
    quay.io/cilium/tetragon-ci:latest                   \
    --config-file /tracing_policy.yaml
```

We added two flags to our commands:
- `-v $(pwd)/tracing_policy.yaml:/tracing_policy.yaml` mounts the created local
  file into the container filesystem.
- `--config-file /tracing_policy.yaml` indicates Tetragon to load the policy in
  the provided file.

Now again, in another terminal, open the `tetra` CLI to see the new events
generated by Tetragon, monitoring the `openat` system call.

```shell
docker exec tetragon-container tetra getevents -o compact
```

And in the third terminal, just read the `tracing_policy.yaml` file we created
using cat with:
```shell
cat tracing_policy.yaml
```

The output from the `tetra` CLI should be similar to:

```
🚀 process  /usr/bin/cat tracingpolicy.yaml
📬️ openat   /usr/bin/cat /etc/ld.so.cache
📬️ openat   /usr/bin/cat /lib/aarch64-linux-gnu/libc.so.6
📬️ openat   /usr/bin/cat tracingpolicy.yaml
💥 exit     /usr/bin/cat tracingpolicy.yaml 0
```

{{< note >}}
The syscall we choose is `openat` and not `open` because the glibc and most of
the implementations of the standard C library use the `openat` syscall for
their `open` wrapper. So `cat` on Linux is using `openat`.
{{< /note >}}

We can see that during the execution of `cat`, because it is dynamically
linked, it used the `openat` syscall to open:
- the cache file for shared libraries `ld.so.cache`;
- the `libc.so.6` library;
- the file we actually wanted to read `tracing_policy.yaml`.

This is the kind of information we could obtain by executing the program with
`strace` for example, but here Tetragon obtains this information directly from
the kernel, transparently for the executed program.

Please note that `tetra` CLI, with the `-o compact` output format,
automatically tried to decode the second argument as a string and printed it
because it has the hardcoded knowledge that the `openat` syscall has an
interesting string as second argument.

You can use `tetra getevents` to retrieve the whole JSON events and see the
complete fields and values retrieved from the event. In our situation the
output should be similar to the following.

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "OjEwMTgzOTUyNjg1NjcwNDoyNjIzNw==",
      "pid": 26237,
      "uid": 1000,
      "cwd": "/home/ubuntu",
      "binary": "/usr/bin/cat",
      "arguments": "tracing_policy.yaml",
      "flags": "execve clone",
      "start_time": "2023-04-06T18:30:03.405730761Z",
      "auid": 1000,
      "parent_exec_id": "OjEwMTczMDEyNTQ3MjUxMDoyNjIwOA==",
      "refcnt": 1
    },
    "parent": {
      "exec_id": "OjEwMTczMDEyNTQ3MjUxMDoyNjIwOA==",
      "pid": 26208,
      "uid": 1000,
      "cwd": "/home/ubuntu",
      "binary": "/bin/bash",
      "flags": "execve clone",
      "start_time": "2023-04-06T18:28:14.004347210Z",
      "auid": 1000,
      "parent_exec_id": "OjEwMTczMDEwMjc2NTg0NjoyNjIwNw==",
      "refcnt": 2
    },
    "function_name": "__x64_sys_openat",
    "args": [
      {
        "int_arg": -100
      },
      {
        "string_arg": "tracing_policy.yaml"
      },
      {
        "int_arg": 0
      }
    ],
    "action": "KPROBE_ACTION_POST"
  },
  "time": "2023-04-06T18:30:03.406205829Z"
}
```

You can see that Tetragon collected information on the process itself, with for
example, the uid, the binary name, the start_time and much more. It also
indicates process parent, `/bin/bash` in this case. This is the common base of
information we also get from the process lifecycle sensors. Finally, we can see
that Tetragon hooked the function `__x64_sys_openat` (for an arm64 host it
would be `__arm64_sys_openat`) and that it also collected the arguments' value.

### Enforcement with TracingPolicy

Let's see how we can modify the previous TracingPolicy to do enforcement with
Tetragon.

{{< warning >}}
This example is just an illustration and should not be used in a production
environment.  There are many challenges in building a production-grade policy,
that go beyond the scope of this guide. For example, filtering an argument for
security can be difficult, especially with file paths. The `openat` syscall can
take relative paths as arguments and even absolute path filtering can often be
bypassed by pseudo filesystems like procfs, for example using a prefix like
`/proc/self/root/` to access `/`.
{{< /warning >}}

#### Overriding return values

First, let's say we don't want to stop any program that would try to open the
`tracing_policy.yaml` but just stop them from actually using the syscall to
open the file, as if they were not unauthorized to access the file. We could
write the following TracingPolicy.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-access"
spec:
  kprobes:
  - call: "sys_openat"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "string"
    selectors:
    - matchBinaries:
      - operator: In
        values:
        - "/usr/bin/cat"
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "tracing_policy.yaml\0"
      matchActions:
      - action: Override
        argError: -1
```

In the above TracingPolicy, we removed the third argument because we don't
need to extract it specifically, and we added two filters in our existing
selector. One `matchArgs` to filter on the value of the index 1 argument, which
contains the pathname to access, and one `matchActions` to perform on action on
a such match.

Replace the content of the policy in the `tracing_policy.yaml` file with the
above and restart Tetragon with the same command as before. If we open tetra
with `docker exec tetragon-container tetra getevents -o compact` and perform a
`cat tracing_policy.yaml` on the side, we should now observe an output similar
to:

```
🚀 process  /usr/bin/cat tracing_policy.yaml
📬️ openat   /usr/bin/cat tracing_policy.yaml
💥 exit     /usr/bin/cat tracing_policy.yaml 1
```

And the `cat tracing_policy.yaml` should return the following error:

```
cat: tracing_policy.yaml: Operation not permitted
```


#### Synchronously stopping the process

Now, let's say that accessing this file in this manner is critical and we want
to stop any process that tries to perform such action immediately. We just need
to modify the `action` in the `matchActions` filter from `Override` to
`Sigkill`.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-access"
spec:
  kprobes:
  - call: "sys_openat"
    syscall: true
    args:
    - index: 0
      type: "int"
    - index: 1
      type: "string"
    selectors:
    - matchBinaries:
      - operator: In
        values:
        - "/usr/bin/cat"
      matchArgs:
      - index: 1
        operator: "Equal"
        values:
        - "tracing_policy.yaml\0"
      matchActions:
      - action: Sigkill
```

Again, replace the content of the policy in the `tracing_policy.yaml` file with
the above and restart Tetragon with the same command as before. If we open
tetra with `docker exec tetragon-container tetra getevents -o compact` and
perform a `cat tracing_policy.yaml` on the side, we should now observe an
output similar to:

```
🚀 process  /usr/bin/cat tracing_policy.yaml
📬️ openat   /usr/bin/cat tracing_policy.yaml
💥 exit     /usr/bin/cat tracing_policy.yaml SIGKILL
```

And the `cat tracing_policy.yaml` should return an error (that is actually
returned by the shell that invoked the program):

```
Killed
```

Now the process will not have the time to catch the error and will be
synchronously terminated as soon as he triggers the kernel function we hooked
with our specified argument values.

{{< caution >}}
Again, the specific filtering is only given as an example, just reading the
file using `cat ./tracing_policy.yaml` will bypass the policies presented here.
{{< /caution >}}

## What's next

- Try Tetragon in [Kubernetes environments](/docs/getting-started/kubernetes-quickstart-guide).
- Learn more about [TracingPolicy in the reference documentation](/docs/reference/tracing-policy).
- See more [use cases for observability with Tetragon](/docs/tetragon-events).
