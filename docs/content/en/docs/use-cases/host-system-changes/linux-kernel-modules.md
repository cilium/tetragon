---
title: "Monitor Linux Kernel Modules"
weight: 1
icon: "overview"
description: "Monitor Linux Kernel Modules operations"
---

Monitoring kernel modules helps to identify processes that load kernel modules to add features,
to the operating system, to alter host system functionality or even hide their behaviour. This
can be used to answer the following questions:

> Which process or container is changing the kernel?

> Which process or container is loading or unloading kernel modules in the cuslter?

> Which process or container requested a feature that triggered the kernel to automatically load a module?

> Are the loaded kernel modules signed?

## Monitor Loading kernel modules

### Kubernetes Environments

After deploying Tetragon, use the [monitor-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml) tracing policy which generates [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events
to trace kernel module operations.

Apply the [monitor-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml) tracing policy:
```shell
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml
```

Then start monitoring for events with `tetra` CLI:
```shell
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents
```

When loading an out of tree module named `kernel_module_hello.ko` with the command `insmod`,
`tetra` CLI will generate the following [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events:

<details><summary> 1. Reading the kernel module from the file system </summary>
<p>

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "OjEzMTg4MTQwNDUwODkwOjgyMDIz",
      "pid": 82023,
      "uid": 0,
      "cwd": "/home/tixxdz/tetragon",
      "binary": "/usr/sbin/insmod",
      "arguments": "contrib/tester-progs/kernel_module_hello.ko",
      "flags": "execve clone",
      "start_time": "2023-08-30T11:01:22.846516679Z",
      "auid": 1000,
      "parent_exec_id": "OjEzMTg4MTM4MjY2ODQyOjgyMDIy",
      "refcnt": 1,
      "tid": 82023
    },
    "parent": {
      "exec_id": "OjEzMTg4MTM4MjY2ODQyOjgyMDIy",
      "pid": 82022,
      "uid": 1000,
      "cwd": "/home/tixxdz/tetragon",
      "binary": "/usr/bin/sudo",
      "arguments": "insmod contrib/tester-progs/kernel_module_hello.ko",
      "flags": "execve",
      "start_time": "2023-08-30T11:01:22.844332959Z",
      "auid": 1000,
      "parent_exec_id": "OjEzMTg1NTE3MTgzNDM0OjgyMDIx",
      "refcnt": 1,
      "tid": 0
    },
    "function_name": "security_kernel_read_file",
    "args": [
      {
        "file_arg": {
          "path": "/home/tixxdz/tetragon/contrib/tester-progs/kernel_module_hello.ko"
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
  "time": "2023-08-30T11:01:22.847554295Z"
}
```

In addition to the process metadata from exec events, [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events contain the arguments of the observed call. In the above case they are:

- `security_kernel_read_file`: the kernel security hook when the kernel loads file specified by user space.
- `file_arg`: the full path of the kernel module on the file system.

</p>
</details>

<details><summary> 2. Finalize loading of kernel modules </summary>
<p>

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "OjEzMTg4MTQwNDUwODkwOjgyMDIz",
      "pid": 82023,
      "uid": 0,
      "cwd": "/home/tixxdz/tetragon",
      "binary": "/usr/sbin/insmod",
      "arguments": "contrib/tester-progs/kernel_module_hello.ko",
      "flags": "execve clone",
      "start_time": "2023-08-30T11:01:22.846516679Z",
      "auid": 1000,
      "parent_exec_id": "OjEzMTg4MTM4MjY2ODQyOjgyMDIy",
      "refcnt": 1,
      "tid": 82023
    },
    "parent": {
      "exec_id": "OjEzMTg4MTM4MjY2ODQyOjgyMDIy",
      "pid": 82022,
      "uid": 1000,
      "cwd": "/home/tixxdz/tetragon",
      "binary": "/usr/bin/sudo",
      "arguments": "insmod contrib/tester-progs/kernel_module_hello.ko",
      "flags": "execve",
      "start_time": "2023-08-30T11:01:22.844332959Z",
      "auid": 1000,
      "parent_exec_id": "OjEzMTg1NTE3MTgzNDM0OjgyMDIx",
      "refcnt": 1,
      "tid": 0
    },
    "function_name": "do_init_module",
    "args": [
      {
        "module_arg": {
          "name": "kernel_module_hello",
          "tainted": [
            "TAINT_OUT_OF_TREE_MODULE",
            "TAINT_UNSIGNED_MODULE"
          ]
        }
      }
    ],
    "action": "KPROBE_ACTION_POST"
  },
  "time": "2023-08-30T11:01:22.847638990Z"
}
```

This [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) event contains:

- `do_init_module`: the function call where the module is finaly loaded.
- [`module_arg`]({{< ref "/docs/reference/grpc-api#kernelmodule" >}}): the kernel module information, it contains:
  - `name`: the name of the kernel module as a string.
  - [`tainted`]({{< ref "/docs/reference/grpc-api#taintedbitstype" >}}): the module tainted flags that will be applied on the kernel. In the example above, it indicates we are loading an out-of-tree module, that is unsigned module which may compromise the integrity of our system.

</p>
</details>

## Monitor Kernel Modules Signature

Kernels compiled with [`CONFIG_MODULE_SIG`](https://docs.kernel.org/admin-guide/module-signing.html) option will check if the modules being loaded were cryptographically signed.
This allows to assert that:

* If the module being loaded is signed, the kernel has its key and the signature verification succeeded.

* The integrity of the system or the kernel was not compromised.

{{< note >}}
Module signing increases security by identifying malicious modules loaded into the kernel. It is also possible to
deny loading such modules if the signature verification fails.
{{< /note >}}

### Kubernetes Environments

After deploying Tetragon, use the [monitor-signed-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-signed-kernel-modules.yaml) tracing policy which generates [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events
to identify if kernel modules are signed or not.

Apply the [monitor-signed-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-signed-kernel-modules.yaml) tracing policy:
```shell
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-signed-kernel-modules.yaml
```

Before going forward, deploy the [`test-pod`](https://raw.githubusercontent.com/cilium/tetragon/main/testdata/specs/testpod.yaml) into the demo-app namespace, which has its security context set to privileged.
This allows to run the demo by mountig an `xfs` file system inside the `test-pod` which requires privileges,
but will also trigger an automatic `xfs` module loading operation.

{{< note >}}
This was tested on an Ubuntu host.
{{< /note >}}


```shell
kubectl create namespace demo-app
kubectl apply -n demo-app -f https://raw.githubusercontent.com/cilium/tetragon/main/testdata/specs/testpod.yaml
```

Start monitoring for events with `tetra` CLI:
```shell
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents
```

In another terminal, kubectl exec into the `test-pod` and run the following commands to create an `xfs` filesystem:
```shell
kubectl exec -it -n demo-app test-pod -- /bin/sh
apk update
dd if=/dev/zero of=loop.xfs bs=1 count=0 seek=32M
ls -lha loop.xfs
apk add xfsprogs
mkfs.xfs -q loop.xfs
mkdir /mnt/xfs.volume
mount -o loop -t xfs loop.xfs /mnt/xfs.volume/
losetup -a | grep xfs
```

Now the xfs filesystem should be mounted at `/mnt/xfs.volume`. To unmount it and release the loop device run:
```shell
umount /mnt/xfs.volume/
```

`tetra` CLI will generate the following events:

<details><summary> 1. Automatic loading of kernel modules </summary>
<p>

First the `mount` command will trigger an automatic operation to load the `xfs` kernel module.

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQxMjc1NTA0OTk5NTcyOjEzMDg3Ng==",
      "pid": 130876,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/mount",
      "arguments": "-o loop -t xfs loop.xfs /mnt/xfs.volume/",
      "flags": "execve rootcwd clone",
      "start_time": "2023-09-09T23:27:42.732039059Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "demo-app",
        "name": "test-pod",
        "container": {
          "id": "containerd://1e910d5cc8d8d68c894934170b162ef93aea5652867ed6bd7c620c7e3f9a10f1",
          "name": "test-pod",
          "image": {
            "id": "docker.io/cilium/starwars@sha256:f92c8cd25372bac56f55111469fe9862bf682385a4227645f5af155eee7f58d9",
            "name": "docker.io/cilium/starwars:latest"
          },
          "start_time": "2023-09-09T22:46:09Z",
          "pid": 45672
        },
        "workload": "test-pod"
      },
      "docker": "1e910d5cc8d8d68c894934170b162ef",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQxMjYyOTc1MjI1MDkzOjEzMDgwOQ==",
      "refcnt": 1,
      "tid": 130876
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQxMjYyOTc1MjI1MDkzOjEzMDgwOQ==",
      "pid": 130809,
      "uid": 0,
      "cwd": "/",
      "binary": "/bin/sh",
      "flags": "execve rootcwd clone",
      "start_time": "2023-09-09T23:27:30.202263472Z",
      "auid": 4294967295,
      "pod": {
        "namespace": "demo-app",
        "name": "test-pod",
        "container": {
          "id": "containerd://1e910d5cc8d8d68c894934170b162ef93aea5652867ed6bd7c620c7e3f9a10f1",
          "name": "test-pod",
          "image": {
            "id": "docker.io/cilium/starwars@sha256:f92c8cd25372bac56f55111469fe9862bf682385a4227645f5af155eee7f58d9",
            "name": "docker.io/cilium/starwars:latest"
          },
          "start_time": "2023-09-09T22:46:09Z",
          "pid": 45612
        },
        "workload": "test-pod"
      },
      "docker": "1e910d5cc8d8d68c894934170b162ef",
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQxMjYyOTEwMjM3OTQ2OjEzMDgwMA==",
      "tid": 130809
    },
    "function_name": "security_kernel_module_request",
    "args": [
      {
        "string_arg": "fs-xfs"
      }
    ],
    "return": {
      "int_arg": 0
    },
    "action": "KPROBE_ACTION_POST"
  },
  "node_name": "kind-control-plane",
  "time": "2023-09-09T23:27:42.751151233Z"
}
```

In addition to the process metadata from exec events, [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) event contains the arguments of the observed call. In the above case they are:

- `security_kernel_module_request`: the kernel security hook where modules are loaded on-demand.
- `string_arg`: the name of the kernel module. When modules are automatically loaded, for security reasons, 
  the kernel prefixes the module with the name of the subsystem that requested it. In our case, it's requested
  by the file system subsystem, hence the name is `fs-xfs`.

</p>
</details>

<details><summary> 2. Kernel calls modprobe to load the kernel module </summary>
<p>

The kernel will then call user space `modprobe` to load the kernel module.

```json
{
  "process_exec": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQxMjc1NTI0MjYzMjIxOjEzMDg3Nw==",
      "pid": 130877,
      "uid": 0,
      "cwd": "/",
      "binary": "/sbin/modprobe",
      "arguments": "-q -- fs-xfs",
      "flags": "execve rootcwd clone",
      "start_time": "2023-09-09T23:27:42.751301124Z",
      "auid": 4294967295,
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE6MA==",
      "tid": 130877
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE6MA==",
      "pid": 0,
      "uid": 0,
      "binary": "<kernel>",
      "flags": "procFS",
      "start_time": "2023-09-09T11:59:47.227037763Z",
      "auid": 0,
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE6MA==",
      "tid": 0
    }
  },
  "node_name": "kind-control-plane",
  "time": "2023-09-09T23:27:42.751300984Z"
}
```

The [ProcessExec]({{< ref "/docs/reference/grpc-api#processexec" >}}) event where `modprobe` tries to load the `xfs` module.

{{< note >}}
Here `modprobe` is started in the initial Linux host namespaces, outside of the container namespaces. When kernel
modules are loaded on-demand, the kernel will spawn a user space process `modprobe` that finds and load the appropriate
module from the host file system. This is done on behalf of the container and since its originate from the kernel then
the inherited Linux namespaces including the file system are eventually from the host.
{{< /note >}}

</p>
</details>

<details><summary> 3. Reading the kernel module from the file system </summary>
<p>

`modprobe` will read the passed `xfs` kernel module from the host file system.

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQxMjc1NTI0MjYzMjIxOjEzMDg3Nw==",
      "pid": 130877,
      "uid": 0,
      "cwd": "/",
      "binary": "/sbin/modprobe",
      "arguments": "-q -- fs-xfs",
      "flags": "execve rootcwd clone",
      "start_time": "2023-09-09T23:27:42.751301124Z",
      "auid": 4294967295,
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE6MA==",
      "refcnt": 1,
      "tid": 130877
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE6MA==",
      "pid": 0,
      "uid": 0,
      "binary": "<kernel>",
      "flags": "procFS",
      "start_time": "2023-09-09T11:59:47.227037763Z",
      "auid": 0,
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE6MA==",
      "tid": 0
    },
    "function_name": "security_kernel_read_file",
    "args": [
      {
        "file_arg": {
          "path": "/usr/lib/modules/6.2.0-32-generic/kernel/fs/xfs/xfs.ko"
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
  "time": "2023-09-09T23:27:42.752425825Z"
}
```

This [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) event contains:

- `security_kernel_read_file`: the kernel security hook when the kernel loads file specified by user space.
- `file_arg`: the full path of the kernel module on the host file system.

</p>
</details>

<details><summary> 4. Kernel module signature and sections are parsed </summary>
<p>

The final event is when the kernel is parsing the module sections. If all succeed the module will be loaded.

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjQxMjc1NTI0MjYzMjIxOjEzMDg3Nw==",
      "pid": 130877,
      "uid": 0,
      "cwd": "/",
      "binary": "/sbin/modprobe",
      "arguments": "-q -- fs-xfs",
      "flags": "execve rootcwd clone",
      "start_time": "2023-09-09T23:27:42.751301124Z",
      "auid": 4294967295,
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE6MA==",
      "refcnt": 1,
      "tid": 130877
    },
    "parent": {
      "exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE6MA==",
      "pid": 0,
      "uid": 0,
      "binary": "<kernel>",
      "flags": "procFS",
      "start_time": "2023-09-09T11:59:47.227037763Z",
      "auid": 0,
      "parent_exec_id": "a2luZC1jb250cm9sLXBsYW5lOjE6MA==",
      "tid": 0
    },
    "function_name": "find_module_sections",
    "args": [
      {
        "module_arg": {
          "name": "xfs",
          "signature_ok": true
        }
      }
    ],
    "action": "KPROBE_ACTION_POST"
  },
  "node_name": "kind-control-plane",
  "time": "2023-09-09T23:27:42.760880332Z"
}
```

This [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) event contains the module argument.

- `find_module_sections`: the function call where the kernel parses the module sections.
- [`module_arg`]({{< ref "/docs/reference/grpc-api#kernelmodule" >}}): the kernel module information, it contains:
  - `name`: the name of the kernel module as a string.
  - `signature_ok`: a boolean value, if set to `true` then module signature was successfully verified by the kernel. If it is `false`
     or missing then the signature verification was not performed or probably failed. In all cases this means the integrity of the system has been compromised. Depends on kernels compiled with [`CONFIG_MODULE_SIG`](https://docs.kernel.org/admin-guide/module-signing.html) option.

</p>
</details>


## Monitor Unloading of kernel modules

Using the same [monitor-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml) tracing policy allows to monitor unloading of kernel modules.

The following [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) event will be generated:

<details><summary> Removing kernel modules event </summary>
<p>

```json
{
  "process_kprobe": {
    "process": {
      "exec_id": "OjMzNzQ4NzY1MDAyNDk5OjI0OTE3NQ==",
      "pid": 249175,
      "uid": 0,
      "cwd": "/home/tixxdz/tetragon",
      "binary": "/usr/sbin/rmmod",
      "arguments": "kernel_module_hello",
      "flags": "execve clone",
      "start_time": "2023-08-30T16:44:03.471068355Z",
      "auid": 1000,
      "parent_exec_id": "OjMzNzQ4NzY0MjQ4MTY5OjI0OTE3NA==",
      "refcnt": 1,
      "tid": 249175
    },
    "parent": {
      "exec_id": "OjMzNzQ4NzY0MjQ4MTY5OjI0OTE3NA==",
      "pid": 249174,
      "uid": 1000,
      "cwd": "/home/tixxdz/tetragon",
      "binary": "/usr/bin/sudo",
      "arguments": "rmmod kernel_module_hello",
      "flags": "execve",
      "start_time": "2023-08-30T16:44:03.470314558Z",
      "auid": 1000,
      "parent_exec_id": "OjMzNzQ2MjA5OTUxODI4OjI0OTE3Mw==",
      "refcnt": 1,
      "tid": 0
    },
    "function_name": "free_module",
    "args": [
      {
        "module_arg": {
          "name": "kernel_module_hello",
          "tainted": [
            "TAINT_OUT_OF_TREE_MODULE",
            "TAINT_UNSIGNED_MODULE"
          ]
        }
      }
    ],
    "action": "KPROBE_ACTION_POST"
  },
  "time": "2023-08-30T16:44:03.471984676Z"
}
```

</p>
</details>

{{< note >}}
Please note that some kernel module rootkits hide themselves by deleting their
entries from the kernel internal module lists while continuing to run in the background.
Monitoring module load operations allows to detect such cases
{{< /note >}}

To disable the [monitor-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml) run:

```shell
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml
```
