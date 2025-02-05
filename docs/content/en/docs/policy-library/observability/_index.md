---
title: "Tetragon Observability Policies"
weight: 3
description: >
  Library of policies that implement Tetragon observability mechanisms.
---


## Index

### Security Sensitive Events

- [Binary Execution in /tmp]({{< ref "#tmp-execs" >}})
- [sudo Monitoring]({{< ref "#sudo" >}})
- [Privileges Escalation via SUID Binary Execution]({{< ref "#privileges-suid" >}})
- [Privileges Escalation via File Capabilities Execution]({{< ref "#privileges-fscaps" >}})
- [Privileges Escalation via Setuid system calls]({{< ref "#privileges-setuid" >}})
- [Privileges Escalation via Unprivileged User Namespaces]({{< ref "#privileges-userns" >}})
- [Privileges Change via Capset system call]({{< ref "#privileges-capset" >}})
- [Fileless Execution]({{< ref "#exec-fileless" >}})
- [Execution of Deleted Binaries]({{< ref "#exec-unlinked" >}})

### System Activity

- [eBPF System Activity]({{< ref "#ebpf" >}})
- [Kernel Module Audit trail]({{< ref "#kernel-module" >}})
- [Shared Library Loading]({{< ref "#library" >}})

### Networking

- [Network Activity of SSH daemon]({{< ref "#ssh" >}})
- [Outbound Connections]({{< ref "#egress-connections" >}})


# Observability Policies

## Binary Execution in /tmp {#tmp-execs}

### Description

Monitor execution of a binary in the /tmp directory.

### Use Case

Preventing execution of executables in `/tmp` is a common best-practice as several canned exploits rely on writing and then executing malicious binaries in the `/tmp` directory. A common best-practice to enforce this is to mount the `/tmp` filesystem with the `noexec` flag. This observability policy is used to monitor for violations of this best practice.

### Policy

No policy needs to be loaded, standard process execution observability is sufficient.

### Example jq Filter

```shell
jq 'select(.process_exec != null) | select(.process_exec.process.binary | contains("/tmp/")) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.pod.name) \(.process_exec.process.binary) \(.process_exec.process.arguments)"'
```

### Example Output

```shell
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

```shell
jq 'select(.process_exec != null) | select(.process_exec.process.binary | contains("sudo")) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.binary) \(.process_exec.process.arguments)"'
```

### Example Output

```shell
"2023-10-31T19:03:35.273111185Z null /usr/bin/sudo -i"
```

## Privileges Escalation via SUID Binary Execution {#privileges-suid}

### Description

Monitor execution of SUID "Set User ID" binaries.

### Use Case

The "Set User Identity" and "Set Group Identity" are permission flags. When set on a binary file, the binary will execute with the permissions
of the owner or group associated with the executable file, rather than the user executing it. Usually it is used to run programs with elevated privileges to perform specific tasks.

Detecting the execution of `setuid` and `setgid` binaries is a common
best-practice as attackers may abuse such binaries, or even create them
during an exploit for subsequent execution.

### Requirement

Tetragon must run with the Process Credentials visibility enabled, please
refer to [Enable Process Credentials]({{< ref "docs/installation/configuration#enable-process-credentials" >}}) documentation.

### Policy

No policy needs to be loaded, standard process execution observability is sufficient.

### Example jq Filter

```shell
jq 'select(.process_exec != null) | select(.process_exec.process.binary_properties != null) | select(.process_exec.process.binary_properties.setuid != null or .process_exec.process.binary_properties.setgid != null) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.pod.name) \(.process_exec.process.binary) \(.process_exec.process.arguments) uid=\(.process_exec.process.process_credentials.uid) euid=\(.process_exec.process.process_credentials.euid)  gid=\(.process_exec.process.process_credentials.gid) egid=\(.process_exec.process.process_credentials.egid) binary_properties=\(.process_exec.process.binary_properties)"'
```

### Example Output

```shell
"2024-02-05T20:20:50.828208246Z null null /usr/bin/sudo id uid=1000 euid=0  gid=1000 egid=1000 binary_properties={\"setuid\":0,\"privileges_changed\":[\"PRIVILEGES_RAISED_EXEC_FILE_SETUID\"]}"
"2024-02-05T20:20:57.008655978Z null null /usr/bin/wall hello uid=1000 euid=1000  gid=1000 egid=5 binary_properties={\"setgid\":5}"
"2024-02-05T20:21:00.116297664Z null null /usr/bin/su --help uid=1000 euid=0  gid=1000 egid=1000 binary_properties={\"setuid\":0,\"privileges_changed\":[\"PRIVILEGES_RAISED_EXEC_FILE_SETUID\"]}"
```

## Privileges Escalation via File Capabilities Execution {#privileges-fscaps}

### Description

Monitor execution of binaries with file capabilities.

### Use Case

File capabilities allow the binary execution to acquire more privileges
to perform specific tasks. They are stored in the extended attribute part
of the binary on the file system. They can be set using the
[setcap](https://man7.org/linux/man-pages/man8/setcap.8.html) tool.

For further reference, please check [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
man page; section `File capabilities`.

Detecting the execution of `file capabilities` binaries is a common
best-practice, since they cross privilege boundaries which make them a suitable
target for attackers. Such binaries are also used by attackers to hide their
privileges after a successful exploit.

### Requirement

Tetragon must run with the Process Credentials visibility enabled, please
refer to [Enable Process Credentials]({{< ref "docs/installation/configuration#enable-process-credentials" >}})
documentation.

### Policy

No policy needs to be loaded, standard process execution observability is sufficient.

### Example jq Filter

```shell
jq 'select(.process_exec != null) | select(.process_exec.process.binary_properties != null) | select(.process_exec.process.binary_properties.privileges_changed != null) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.pod.name) \(.process_exec.process.binary) \(.process_exec.process.arguments) uid=\(.process_exec.process.process_credentials.uid) euid=\(.process_exec.process.process_credentials.euid)  gid=\(.process_exec.process.process_credentials.gid) egid=\(.process_exec.process.process_credentials.egid) caps=\(.process_exec.process.cap) binary_properties=\(.process_exec.process.binary_properties)"'
```

### Example Output

```shell
"2024-02-05T20:49:39.551528684Z null null /usr/bin/ping ebpf.io uid=1000 euid=1000  gid=1000 egid=1000 caps={\"permitted\":[\"CAP_NET_RAW\"],\"effective\":[\"CAP_NET_RAW\"]} binary_properties={\"privileges_changed\":[\"PRIVILEGES_RAISED_EXEC_FILE_CAP\"]}"
```

## Privileges Escalation via Setuid System Calls {#privileges-setuid}

### Description

Monitor execution of the [setuid()](https://www.man7.org/linux/man-pages/man2/setuid.2.html) system calls family.

### Use Case

The [setuid()](https://www.man7.org/linux/man-pages/man2/setuid.2.html) and [setgid()](https://www.man7.org/linux/man-pages/man2/setgid.2.html)
system calls family allow to change the effective user ID and group ID of the calling process.

Detecting [setuid()](https://www.man7.org/linux/man-pages/man2/setuid.2.html) and [setgid()](https://www.man7.org/linux/man-pages/man2/setgid.2.html) calls that set the user ID or group ID to root is a common
best-practice to identify when privileges are raised.

### Policy

The [privileges-raise.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/privileges/privileges-raise.yaml) monitors the various interfaces of `setuid()` and `setgid()` to root.

### Example jq Filter

```shell
jq 'select(.process_kprobe != null) | select(.process_kprobe.policy_name | test("privileges-raise")) | select(.process_kprobe.function_name | test("__sys_")) | "\(.time) \(.process_kprobe.process.pod.namespace) \(.process_kprobe.process.pod.name) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) \(.process_kprobe.function_name) \(.process_kprobe.args)"'
```

### Example Output

```shell
"2024-02-05T15:23:24.734543507Z null null /usr/local/sbin/runc --root /run/containerd/runc/k8s.io --log /run/containerd/io.containerd.runtime.v2.task/k8s.io/024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392/log.json --log-format json --systemd-cgroup exec --process /tmp/runc-process2191655094 --detach --pid-file /run/containerd/io.containerd.runtime.v2.task/k8s.io/024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392/2d56fcb136b07310685c9e188be7a49d32dc0e45a10d3fe14bc550e6ce2aa5cb.pid 024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392 __sys_setuid [{\"int_arg\":0}]"
"2024-02-05T15:23:24.734550826Z null null /usr/local/sbin/runc --root /run/containerd/runc/k8s.io --log /run/containerd/io.containerd.runtime.v2.task/k8s.io/024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392/log.json --log-format json --systemd-cgroup exec --process /tmp/runc-process2191655094 --detach --pid-file /run/containerd/io.containerd.runtime.v2.task/k8s.io/024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392/2d56fcb136b07310685c9e188be7a49d32dc0e45a10d3fe14bc550e6ce2aa5cb.pid 024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392 __sys_setgid [{\"int_arg\":0}]"
"2024-02-05T15:23:28.731719921Z null null /usr/bin/sudo id __sys_setresgid [{\"int_arg\":-1},{\"int_arg\":0},{\"int_arg\":-1}]"
"2024-02-05T15:23:28.731752014Z null null /usr/bin/sudo id __sys_setresuid [{\"int_arg\":-1},{\"int_arg\":0},{\"int_arg\":-1}]"
"2024-02-05T15:23:30.803946368Z null null /usr/bin/sudo id __sys_setgid [{\"int_arg\":0}]"
"2024-02-05T15:23:30.805118893Z null null /usr/bin/sudo id __sys_setresuid [{\"int_arg\":0},{\"int_arg\":0},{\"int_arg\":0}]"
```

## Privileges Escalation via Unprivileged User Namespaces {#privileges-userns}

### Description

Monitor creation of [User namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
by unprivileged.

### Use Case

User namespaces isolate security-related identifiers like user IDs, group IDs
[credentials](https://man7.org/linux/man-pages/man7/credentials.7.html) and
[capabilities](https://www.man7.org/linux/man-pages/man7/capabilities.7.html).
A process can have a normal unprivileged user ID outside a user namespace
while at the same time having a privileged user ID 0 (root) inside its own
user namespace.

When an unprivileged process creates a new user namespace beside having a
privileged user ID, it will also receive the full set of capabilities. User
namespaces are feature to replace `setuid` and `setgid` binaries, and to allow
applications to create sandboxes. However, they expose lot of kernel
interfaces that are normally restricted to privileged (root). Such interfaces
may increase the attack surface and get abused by attackers in order to
perform privileges escalation exploits.

Unfortunatly, a [report from Google](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html)
shows up that 44% of the exploits required unprivileged user namespaces to
perform chain privileges escalation. Therfore, detecting the creation of user
namespaces by unprivileged is a common best-practice to identify such cases.

### Policy

The [privileges-raise.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/privileges/privileges-raise.yaml)
monitors the creation of user namespaces by unprivileged.

### Example jq Filter

```shell
jq 'select(.process_kprobe != null) | select(.process_kprobe.policy_name | test("privileges-raise")) | select(.process_kprobe.function_name | test("create_user_ns")) | "\(.time) \(.process_kprobe.process.pod.namespace) \(.process_kprobe.process.pod.name) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) \(.process_kprobe.function_name) \(.process_kprobe.process.process_credentials)"'
```

### Example Output

```shell
"2024-02-05T22:08:15.033035972Z null null /usr/bin/unshare -rUfp create_user_ns {\"uid\":1000,\"gid\":1000,\"euid\":1000,\"egid\":1000,\"suid\":1000,\"sgid\":1000,\"fsuid\":1000,\"fsgid\":1000}"
```

## Privileges Change via Capset System Call {#privileges-capset}

### Description

Monitor execution of the [capset()](https://www.man7.org/linux/man-pages/man2/capset.2.html)
system call.

### Use Case

The [capset()](https://www.man7.org/linux/man-pages/man2/capset.2.html)
system call allows to change the process [capabilities](https://www.man7.org/linux/man-pages/man7/capabilities.7.html).

Detecting [capset()](https://www.man7.org/linux/man-pages/man2/capset.2.html)
calls that set the effective, inheritable and permitted capabilities to non
zero is a common best-practice to identify processes that could raise their
privileges.

### Policy

The [privileges-raise.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/privileges/privileges-raise.yaml)
monitors `capset()` calls that do not drop capabilities.

### Example jq Filter

```shell
jq 'select(.process_kprobe != null) | select(.process_kprobe.policy_name | test("privileges-raise")) | select(.process_kprobe.function_name | test("capset")) | "\(.time) \(.process_kprobe.process.pod.namespace) \(.process_kprobe.process.pod.name) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) \(.process_kprobe.function_name) \(.process_kprobe.args[3]) \(.process_kprobe.args[1])"'
```

### Example Output

```shell
"2024-02-05T21:12:03.579600653Z null null /usr/bin/sudo id security_capset {\"cap_permitted_arg\":\"000001ffffffffff\"} {\"cap_effective_arg\":\"000001ffffffffff\"}"
"2024-02-05T21:12:04.754115578Z null null /usr/local/sbin/runc --root /run/containerd/runc/k8s.io --log /run/containerd/io.containerd.runtime.v2.task/k8s.io/024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392/log.json --log-format json --systemd-cgroup exec --process /tmp/runc-process2431693392 --detach --pid-file /run/containerd/io.containerd.runtime.v2.task/k8s.io/024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392/9403a57a3061274de26cad41915bad5416d4d484c9e142b22193b74e19a252c5.pid 024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392 security_capset {\"cap_permitted_arg\":\"000001ffffffffff\"} {\"cap_effective_arg\":\"000001ffffffffff\"}"
"2024-02-05T21:12:12.836813445Z null null /usr/bin/runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v2.task/moby/c7bc6bf80f07bf6475e507f735866186650137bca2be796d6a39e22b747b97e9/log.json --log-format json --systemd-cgroup create --bundle /run/containerd/io.containerd.runtime.v2.task/moby/c7bc6bf80f07bf6475e507f735866186650137bca2be796d6a39e22b747b97e9 --pid-file /run/containerd/io.containerd.runtime.v2.task/moby/c7bc6bf80f07bf6475e507f735866186650137bca2be796d6a39e22b747b97e9/init.pid c7bc6bf80f07bf6475e507f735866186650137bca2be796d6a39e22b747b97e9 security_capset {\"cap_permitted_arg\":\"00000000a80425fb\"} {\"cap_effective_arg\":\"00000000a80425fb\"}"
"2024-02-05T21:12:14.774175889Z null null /usr/local/sbin/runc --root /run/containerd/runc/k8s.io --log /run/containerd/io.containerd.runtime.v2.task/k8s.io/024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392/log.json --log-format json --systemd-cgroup exec --process /tmp/runc-process2888400204 --detach --pid-file /run/containerd/io.containerd.runtime.v2.task/k8s.io/024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392/d8b8598320fe3d874b901c70863f36233760b3e63650a2474f707cc51b4340f9.pid 024daa4cc70eb683355f6f67beda3012c65d64f479d958e421cd209738a75392 security_capset {\"cap_permitted_arg\":\"000001ffffffffff\"} {\"cap_effective_arg\":\"000001ffffffffff\"}"
```

## Fileless Execution {#exec-fileless}

### Description

Monitor the execution of binaries that exist exclusively as a computer
memory-based artifact.

### Use Case

Often attackers execute fileless binaries that reside only in memory
rather than on the file system to cover their traces. On Linux this
is possible with the help of [memfd_create()](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
and [shared memory](https://man7.org/linux/man-pages/man7/shm_overview.7.html)
anonymous files. Therefore, detecting execution of such binaries that
live only in RAM or backed by volatile storage is a common best-practice.

### Requirement

Tetragon must run with the Process Credentials visibility enabled, please
refer to [Enable Process Credentials]({{< ref "docs/installation/configuration#enable-process-credentials" >}})
documentation.

### Policy

No policy needs to be loaded, standard process execution observability is
sufficient.

### Demo to reproduce

You can use the [exec-memfd.py](https://raw.githubusercontent.com/cilium/tetragon/main/testdata/demos/tools/exec-memfd.py)
python script as an example which will copy the binary `/bin/true` into
an anonymous memory then execute it. The binary will not be linked on the
file system.

### Example jq Filter

```shell
jq 'select(.process_exec != null) | select(.process_exec.process.binary_properties != null) | select(.process_exec.process.binary_properties.file) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.pod.name) \(.process_exec.process.binary) \(.process_exec.process.arguments) uid=\(.process_exec.process.process_credentials.uid) euid=\(.process_exec.process.process_credentials.euid) binary_properties=\(.process_exec.process.binary_properties)"'
```

### Example Output

```shell
"2024-02-14T15:17:48.758997159Z null null /proc/self/fd/3 null uid=1000 euid=1000 binary_properties={\"file\":{\"inode\":{\"number\":\"45021\",\"links\":0}}}"
```

The output shows that the executed binary refers to a file descriptor
`/proc/self/fd/3` that it is not linked on the file system.
The [binary_properties]({{< ref "/docs/reference/grpc-api#binaryproperties" >}})
includes an [inode]({{< ref "/docs/reference/grpc-api#inodeproperties" >}})
with zero links on the file system.

## Execution of Deleted Binaries {#exec-unlinked}

### Description

Monitor the execution of deleted binaries.

### Use Case

Malicious actors may open a binary, delete it from the file system to hide
their traces then execute it. Detecting such executions is a good pratice.

### Requirement

Tetragon must run with the Process Credentials visibility enabled, please
refer to [Enable Process Credentials]({{< ref "docs/installation/configuration#enable-process-credentials" >}})
documentation.

### Policy

No policy needs to be loaded, standard process execution observability is
sufficient.

### Example jq Filter

```shell
jq 'select(.process_exec != null) | select(.process_exec.process.binary_properties != null) | select(.process_exec.process.binary_properties.file != null) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.pod.name) \(.process_exec.process.binary) \(.process_exec.process.arguments) uid=\(.process_exec.process.process_credentials.uid) euid=\(.process_exec.process.process_credentials.euid) binary_properties=\(.process_exec.process.binary_properties)"'
```

### Example Output

```shell
"2024-02-14T16:07:54.265540484Z null null /proc/self/fd/14 null uid=1000 euid=1000 binary_properties={\"file\":{\"inode\":{\"number\":\"4991635\",\"links\":0}}}"
```

The output shows that the executed binary refers to a file descriptor
`/proc/self/fd/14` that it is not linked on the file system.
The [binary_properties]({{< ref "/docs/reference/grpc-api#binaryproperties" >}})
includes an [inode]({{< ref "/docs/reference/grpc-api#inodeproperties" >}})
with zero links on the file system.

## eBPF Subsystem Interactions {#ebpf}

### Description

Audit BPF program loads and BPFFS interactions

### Use Case

Understanding BPF programs loaded in a cluster and interactions between applications
and programs can identify bugs and malicious or unexpected BPF activity.

### Policy

[bpf.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/bpf.yaml)

### Example jq Filter

```shell
jq 'select(.process_kprobe != null) | select(.process_kprobe.function_name | test("bpf_check")) | "\(.time) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) programType:\(.process_kprobe.args[0].bpf_attr_arg.ProgType) programInsn:\(.process_kprobe.args[0].bpf_attr_arg.InsnCnt)"'
```

### Example Output

```shell
"2023-11-01T02:56:54.926403604Z /usr/bin/bpftool prog list programType:BPF_PROG_TYPE_SOCKET_FILTER programInsn:2"
```

## Kernel Module Audit Trail {#kernel-module}

### Description

Audit loading of kernel modules

### Use Case

Understanding exactly what kernel modules are running in the cluster is crucial to understand attack surface and any malicious actors loading unexpected modules.

### Policy

[modules.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/modules.yaml)

### Example jq Filter

```shell
jq 'select(.process_kprobe != null) | select(.process_kprobe.function_name | test("security_kernel_module_request"))  | "\(.time) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) module:\(.process_kprobe.args[0].string_arg)"'
```

### Example Output

```shell
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

```shell
jq 'select(.process_loader != null) | "\(.time) \(.process_loader.process.pod.namespace) \(.process_loader.process.binary) \(.process_loader.process.arguments) \(.process_loader.path)"'
```

### Example Output

```shell
"2023-10-31T19:42:33.065233159Z default/xwing /usr/bin/curl https://ebpf.io /usr/lib/x86_64-linux-gnu/libssl.so.3"
```

## SSHd connection monitoring {#ssh-network}

### Description

Monitor sessions to SSHd

### Use Case

It is best practice to audit remote connections into a shell server.

### Policy

[sshd.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/sshd.yaml)

### Example jq Filter

```shell
jq 'select(.process_kprobe != null) | select(.process_kprobe.function_name | test("tcp_close")) |  "\(.time) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) \(.process_kprobe.args[0].sock_arg.family) \(.process_kprobe.args[0].sock_arg.type)  \(.process_kprobe.args[0].sock_arg.protocol) \(.process_kprobe.args[0].sock_arg.saddr):\(.process_kprobe.args[0].sock_arg.sport)"'
```

### Example Output

```shell
"2023-11-01T04:51:20.109146920Z /usr/sbin/sshd default/xwing AF_INET SOCK_STREAM IPPROTO_TCP 127.0.0.1:22"
```

## Outbound connections {#egress-connections}

### Description

Monitor all cluster egress connections

### Use Case

Connections made outside a Kubernetes cluster can be audited to provide insights
into any unexpected or malicious reverse shells.

### Environment Variables

```shell
PODCIDR=`kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'`
```

{{< tabpane lang=shell >}}

{{< tab GKE >}}
SERVICECIDR=$(gcloud container clusters describe ${NAME} --zone ${ZONE} | awk '/servicesIpv4CidrBlock/ { print $2; }')
{{< /tab >}}

{{< tab Kind >}}
SERVICECIDR=$(kubectl describe pod -n kube-system kube-apiserver-kind-control-plane | awk -F= '/--service-cluster-ip-range/ {print $2; }')
{{< /tab >}}

{{< /tabpane >}}

### Policy

[egress.yaml](https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/egress.yaml)

### Example jq Filter

```shell
jq 'select(.process_kprobe != null) | select(.process_kprobe.function_name | test("tcp_connect")) | "\(.time) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) \(.process_kprobe.args[0].sock_arg.saddr):\(.process_kprobe.args[0].sock_arg.sport) -> \(.process_kprobe.args[0].sock_arg.daddr):\(.process_kprobe.args[0].sock_arg.dport)"'
```

### Example Output

```shell
"2023-11-01T05:25:14.837745007Z /usr/bin/curl http://ebpf.io 10.168.0.45:48272 -> 104.198.14.52:80"
```
