---
title: "Monitor Linux Kernel Modules"
weight: 1
icon: "overview"
description: "Monitor Linux Kernel Modules operations"
---

Monitoring kernel modules helps to identify processes that load kernel modules to add features,
to the operating system, to alter host system functionality or even hide their behaviour.

The [monitor-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml) tracing policy can be used to answer the following questions:

> Which process or container is changing the kernel?

> Which process or container is loading or unloading kernel modules in the cuslter?

> Which process or container requested a feature that triggered the kernel to automatically load a module?

## Monitor Loading kernel modules

### Kubernetes Environments

After deploying Tetragon, use the [monitor-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml) tracing policy which generates [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events
to trace kernel module operations.

Apply the [monitor-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml) tracing policy:
```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml
```

Then start monitoring for events with `tetra` CLI:
```shell-session
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents
```

When loading an out of tree module named `kernel_module_hello.ko` with the command `insmod`,
`tetra` CLI will generate the following [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events:

Reading module file event:
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

Loading the module:
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

In addition to the process metadata from exec events, [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) events contain the arguments of the observed call. In the above case they are:

* Reading the kernel module file:
   - `security_kernel_read_file`: the kernel security hook when the kernel loads file specified by user space.
   - `file_arg`: the full path of the kernel module on the file system.

* Parsing the kernel module sections:
   - `do_init_module`: the function call where module sections are parsed.
   - [`module_arg`]({{< ref "/docs/reference/grpc-api#kernelmodule" >}}): the kernel module information, it contains:
      - `name`: the name of the kernel module as a string.
      - [`tainted`]({{< ref "/docs/reference/grpc-api#taintedbitstype" >}}): the module tainted flags that will be applied on the kernel. Here it indicates we are loading an out of tree module, and an unsigned module which may compromise the integrity of our system.

## Monitor Unloading of kernel modules

Using the same [monitor-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml) tracing policy allows to monitor unloading of kernel modules.

The following [ProcessKprobe]({{< ref "/docs/reference/grpc-api#processkprobe" >}}) event will be generated:

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

{{< note >}}
Please note that some kernel module rootkits hide themselves by deleting their
entries from the kernel internal module lists while continuing to run in the background.
Monitoring module load operations allows to detect such cases
{{< /note >}}

To disable the [monitor-kernel-modules](https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml) run:

```shell-session
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/host-changes/monitor-kernel-modules.yaml
```
