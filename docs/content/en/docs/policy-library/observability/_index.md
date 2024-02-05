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
- [SUID Binary Execution]({{< ref "#suid" >}})
- [Setuid system calls]({{< ref "#setuid" >}})

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

```shell
jq 'select(.process_kprobe != null) | select(.process_kprobe.function_name | test("bpf_check")) | "\(.time) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) programType:\(.process_kprobe.args[0].bpf_attr_arg.ProgType) programInsn:\(.process_kprobe.args[0].bpf_attr_arg.InsnCnt)"
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
jq 'select(.process_loader != null) | "\(.time) \(.process_loader.process.pod.namespace) \(.process_loader.process.binary) \(.process_loader.process.arguments) \(.process_loader.path)"
```

### Example Output

```shell
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

## SUID Binary Execution {#suid}

### Description

Monitor execution of SUID "Set User ID" binaries.

### Use Case

The "Set User Identity" and "Set Group Identity" are permission flags. When set on a binary file, the binary will execute with the permissions
of the owner or group associated with the executable file, rather than the user executing it. Usually it is used to run programs with elevated privileges to perform specific tasks.

Detecting the execution of `setuid` and `setgid` binaries is a common
best-practice as attackers may abuse such binaries, or even create them
during an exploit for subsequent execution.

### Requirement

Run Tetragon with `enable-process-creds` setting set to enable visibility
into [process_credentials]({{< ref "/docs/reference/grpc-api#processcredentials" >}}) and [binary_properties]({{< ref "/docs/reference/grpc-api#binaryproperties" >}}).

{{< tabpane lang=shell >}}

{{< tab Kubernetes >}}
kubectl edit cm -n kube-system tetragon-config
# Change "enable-process-cred" from "false" to "true", then save and exit
# Restart Tetragon daemonset
kubectl rollout restart -n kube-system ds/tetragon
{{< /tab >}}
{{< tab docker >}}
docker run --name tetragon --rm -d \
  --pid=host --cgroupns=host --privileged \
  -v /sys/kernel:/sys/kernel \
  -v /var/log/tetragon:/var/log/tetragon \
  quay.io/cilium/tetragon:{{< latest-version >}} \
  /usr/bin/tetragon --enable-process-cred \
  --export-filename /var/log/tetragon/tetragon.log
{{< /tab >}}
{{< tab systemd >}}
# Write to the drop-in file /etc/tetragon/tetragon.conf.d/enable-process-cred  true
# Run the following as a privileged user then restart tetragon service
echo "true" > /etc/tetragon/tetragon.conf.d/enable-process-cred
systemctl restart tetragon
{{< /tab >}}
{{< /tabpane >}}

### Policy

No policy needs to be loaded, standard process execution observability is sufficient.

### Example jq Filter

```shell
jq 'select(.process_exec != null) | select(.process_exec.process.binary_properties != null) | select(.process_exec.process.binary_properties.setuid != null or .process_exec.process.binary_properties.setgid != null) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.pod.name) \(.process_exec.process.binary) \(.process_exec.process.arguments) uid=\(.process_exec.process.process_credentials.uid) euid=\(.process_exec.process.process_credentials.euid)  gid=\(.process_exec.process.process_credentials.gid) egid=\(.process_exec.process.process_credentials.egid)"'
```

### Example Output

```shell
"2023-11-13T08:20:43.615672640Z null null /usr/bin/sudo id uid=1000 euid=0  gid=1000 egid=1000"
"2023-11-13T08:20:45.591560940Z null null /usr/bin/wall hello uid=1000 euid=1000  gid=1000 egid=5"
"2023-11-13T08:20:47.036760043Z null null /usr/bin/su - uid=1000 euid=0  gid=1000 egid=1000"
```

## Setuid System Calls {#setuid}

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

```shell-sessoin
 jq 'select(.process_kprobe != null) | select(.process_kprobe.function_name | test("tcp_connect")) | "\(.time) \(.process_kprobe.process.binary) \(.process_kprobe.process.arguments) \(.process_kprobe.args[0].sock_arg.saddr):\(.process_kprobe.args[0].sock_arg.sport) -> \(.process_kprobe.args[0].sock_arg.daddr):\(.process_kprobe.args[0].sock_arg.dport)"'
```

### Example Output

```shell
"2023-11-01T05:25:14.837745007Z /usr/bin/curl http://ebpf.io 10.168.0.45:48272 -> 104.198.14.52:80"
```
