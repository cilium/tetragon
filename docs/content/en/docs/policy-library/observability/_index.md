---
title: "Tetragon Observability Policies"
weight: 3
description: >
  Library of policies that implement Tetragon observability and runtime enforcement.
  mechanisms.
---


## Index

### System Activity

- [eBPF System Activity]({{< ref "#ebpf" >}})
- [Kernel Module Audit trail]({{< ref "#kernel-module" >}})
- [Shared Library Loading]({{< ref "#library" >}})

### Security Sensitive Events

- [Binary Execution in /tmp]({{< ref "#tmp-execs" >}})
- [sudo Monitoring]({{< ref "#sudo" >}})

### Networking

- [Network Activity of SSH daemon]({{< ref "#ssh" >}})
- [Outbound Connections]({{< ref "#egress-connections" >}})


# Observability Policies

## eBPF Subsystem Interactions {#ebpf}

### Description

Audit BPF program loads and BPFFS interactions

### Use Case

Understanding BPF programs loaded in a cluster and interactions between applications
and programs can identify bugs and malicious or unexpected BPF activity.

### Policy

[bpf.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/bpf.yaml)

### Example jq Filter

```shell-session
jq 'select(.process_kprobe != null) | select(.process_kprobe.function_name | test("bpf_check")) | "\(.time) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) programType:\(.process_kprobe.args[0].bpf_attr_arg.ProgType) programInsn:\(.process_kprobe.args[0].bpf_attr_arg.InsnCnt)"
```

### Example Output

```shell-session
"2023-11-01T02:56:54.926403604Z /usr/bin/bpftool prog list programType:BPF_PROG_TYPE_SOCKET_FILTER programInsn:2"
```

## Kernel Module Audit Trail {#kernel-module}

### Description

Audit loading of kernel modules

### Use Case

Understanding exactly what kernel modules are running in the cluster is crucial to understand attack surface and any malicious actors loading unexpected modules.

### Policy

[module.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/module.yaml)

### Example jq Filter

```shell-session
 jq 'select(.process_kprobe != null) | select(.process_kprobe.function_name | test("security_kernel_module_request"))  | "\(.time) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) module:\(.process_kprobe.args[0].string_arg)"'
```

### Example Output

```shell-session
"2023-11-01T04:11:38.390880528Z /sbin/iptables -A OUTPUT -m cgroup --cgroup 1 -j LOG module:ipt_LOG"
```

## Shared Library Loading {#library}

### Description

Monitor loading of libraries

### Use Case

Understanding the exact versions of shared libraries that binaries load and use is crucial to understand use of vulnerable or deprecated library versions or attacks such as shared library hijacking.

### Policy

[library.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/library.yaml)


### Example jq Filter

```shell-session
jq 'select(.process_loader != null) | "\(.time) \(.process_loader.process.pod.namespace) \(.process_loader.process.binary) \(.process_loader.process.arguments) \(.process_loader.path)"
```

### Example Output

```shell-session
"2023-10-31T19:42:33.065233159Z default/xwing /usr/bin/curl https://ebpf.io /usr/lib/x86_64-linux-gnu/libssl.so.3"
```

## Binary Execution in /tmp {#tmp-execs}

### Description

Monitor execution of a binary in the /tmp directory.

### Use Case

Preventing execution of executables in `/tmp` is a common best-practice as several canned exploits rely on writing and then executing malicious binaries in the `/tmp` directory. A common best-practice to enforce this is to mount the `/tmp` filesystem with the `noexec` flag. This observability policy is used to monitor for violations of this best practice.

### Policy

No policy needs to be loaded, standard process execution observability is sufficient.

### Example jq Filter

```shell-session
jq 'select(.process_exec != null) | select(.process_exec.process.binary | contains("/tmp/")) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.pod.name) \(.process_exec.process.binary) \(.process_exec.process.arguments)"'
```

### Example Output

```shell-session
"2023-10-31T18:44:22.777962637Z default/xwing /tmp/nc ebpf.io 1234"
```

## sudo Invocation Monitoring {#sudo}

### Description

Monitor sudo invocations

### Use Case

sudo is used to run executables with particular privileges. Creating a audit log of sudo invocations is a common best-practice.

### Policy

No policy needs to be loaded, standard process execution observability is sufficient.

### Example jq Filter

```shell-session
jq 'select(.process_exec != null) | select(.process_exec.process.binary | contains("sudo")) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.binary) \(.process_exec.process.arguments)"'
```

### Example Output

```shell-session
"2023-10-31T19:03:35.273111185Z null /usr/bin/sudo -i"
```

## SSHd connection monitoring {#ssh-network}

### Description

Monitor sessions to SSHd 

### Use Case

It is best practice to audit remote connections into a shell server.

### Policy

[sshd.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/sshd.yaml)

### Example jq Filter

```shell-session
 jq 'select(.process_kprobe != null) | select(.process_kprobe.function_name | test("tcp_close")) |  "\(.time) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) \(.process_kprobe.args[0].sock_arg.family) \(.process_kprobe.args[0].sock_arg.type)  \(.process_kprobe.args[0].sock_arg.protocol) \(.process_kprobe.args[0].sock_arg.saddr):\(.process_kprobe.args[0].sock_arg.sport)"'
```

### Example Output
```shell-session
"2023-11-01T04:51:20.109146920Z /usr/sbin/sshd default/xwing AF_INET SOCK_STREAM IPPROTO_TCP 127.0.0.1:22"
```

## Outbound connections {#egress-connections}

### Description

Monitor all cluster egress connections

### Use Case

Connections made outside a Kubernetes cluster can be audited to provide insights
into any unexpected or malicious reverse shells.

### Policy

[egress.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/egress.yaml)

### Example jq Filter

### Example Output
