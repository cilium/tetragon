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

### Networking

- [Network Activity of SSH daemon]({{< ref "#ssh" >}})
- [Outbound Connections]({{< ref "#egress-connections" >}})


# Observability Policies

## eBPF Subsystem Interactions {#ebpf}

This policy adds monitoring of all BPF programs loaded and file operations over the
BPFFS. The BPFFS is where map file descriptors live allowing programs access to the
BPF user to kernel space.

To apply the policy use kubect apply,

```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/bpf.yaml
```

Now we can do inspect the data to learn interesting things about the system. For example
to find all loaded programs on the system,

```shell-session

```

Or all programs writing to a BPF map,

```shell-session
```

Similarly we might be concerned about all reads,

```shell-session
```

Continue to explore the data set to learn interesting things here.

## Kernel Module Audit Trail {#kernel-module}

This policy adds monitoring of all BPF programs loaded and file operations over the
BPFFS. The BPFFS is where map file descriptors live allowing programs access to the
BPF user to kernel space.

To apply the policy use kubect apply,

```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/bpf.yaml
```

Now we can do inspect the data to learn interesting things about the system. For example
to find all loaded programs on the system,

```shell-session

```

Or all programs writing to a BPF map,

```shell-session
```

Similarly we might be concerned about all reads,

```shell-session
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
"2023-10-31T19:42:33.065233159Z null /usr/bin/curl https://ebpf.io /usr/lib/x86_64-linux-gnu/libssl.so.3"
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

{{< tabpane lang=shell-session >}}

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
  quay.io/cilium/tetragon:{{< latest-version >}} \
  /usr/bin/tetragon --enable-process-cred \
  --export-filename /var/log/tetragon/tetragon.log
{{< /tab >}}
{{< tab systemd >}}
{{< /tab >}}
{{< /tabpane >}}

### Policy

No policy needs to be loaded, standard process execution observability is sufficient.

### Example jq Filter

```shell-session
jq 'select(.process_exec != null) | select(.process_exec.process.binary_properties != null) | select(.process_exec.process.binary_properties.setuid != null or .process_exec.process.binary_properties.setgid != null) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.pod.name) \(.process_exec.process.binary) \(.process_exec.process.arguments)  uid=\(.process_exec.process.process_credentials.uid) gid=\(.process_exec.process.process_credentials.gid)  euid=\(.process_exec.process.process_credentials.euid) egid=\(.process_exec.process.process_credentials.egid)"'
```

### Example Output

```shell-session
"2023-10-31T23:32:50.258640631Z null null /usr/bin/sudo id  uid=1000 gid=1000  euid=0 egid=1000"
"2023-10-31T23:46:49.237690172Z null null /usr/bin/wall hello  uid=1000 gid=1000  euid=1000 egid=5"
"2023-10-31T23:47:06.318192443Z null null /usr/bin/su - root  uid=1000 gid=1000  euid=0 egid=1000"
```

## SSHd connection monitoring {#ssh-network}

This policy adds monitoring of all network connections accepted by SSHd to Tetragon.

To apply the policy use kubect apply,

```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/acceptsshd.yaml
```

To find all sessions over SSHd,

```shell-session

```

## Outbound connections {#egress-connections}

This policy adds monitoring of all BPF programs loaded and file operations over the
BPFFS. The BPFFS is where map file descriptors live allowing programs access to the
BPF user to kernel space.

To apply the policy use kubect apply,

```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/bpf.yaml
```

Now we can do inspect the data to learn interesting things about the system. For example
to find all loaded programs on the system,

```shell-session

```

Or all programs writing to a BPF map,

```shell-session
```

Similarly we might be concerned about all reads,

```shell-session
```

Continue to explore the data set to learn interesting things here.
