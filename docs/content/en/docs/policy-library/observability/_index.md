---
title: "Tetragon Observability Policies"
weight: 3
description: >
  Library of policies that implement Tetragon observability and runtime enforcement.
  mechanisms.
---


## Index

### System Activity

- [eBPF activity]({{< ref "#ebpf" >}})
- [Kernel module audit trail]({{< ref "#kernel-module" >}})
- [Library loading]({{< ref "#library" >}})

### Security Sensitive Events

- [Binary execution in /tmp]({{< ref "#tmp-execs" >}})
- [sudo Monitoring]({{< ref "#sudo" >}})

### Networking

- [Network activity of SSH daemon]({{< ref "#ssh" >}})
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


## Library version monitoring {#library}

This policy adds library monitoring to Tetragon.

To apply the policy use kubect apply,

```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/library.yaml
```

This will record library loads. To find all use of a specific library use
the following, in this case checking libssl library.

```shell-session
$ kubectl logs -n kube-system ds/tetragon -c export-stdout | jq 'select(.process_loader != null) | select(.process_loader.path | contains("ssl")) | "\(.time) \(.process_loader.process.pod.namespace) \(.process_loader.process.binary) \(.process_loader.process.arguments) \(.process_loader.path)"
"2023-10-31T19:42:33.065233159Z null /usr/bin/curl https://ebpf.io /usr/lib/x86_64-linux-gnu/libssl.so.3"
```

We can further restrict to only find versions before some number by adding
a versoin check to find libbssl.so.2 or libssl.so.1 usage in the cluster.

```shell-session
$ kubectl logs -n kube-system ds/tetragon -c export-stdout | jq 'select(.process_loader != null) | select(.process_loader.path | test(".*ssl.so.[2,1]")) | "\(.time) \(.process_loader.process.pod.namespace) \(.process_loader.process.binary) \(.process_loader.process.arguments) \(.process_loader.path)"'
"2023-10-31T19:42:33.065233159Z null /usr/bin/curl https://ebpf.io /usr/lib/x86_64-linux-gnu/libssl.so.2"
```

## Binary Execution in /tmp {#tmp-execs}

This policy adds monitoring of any executions in the /tmp directory.

For this we can simply query the default execution data showing even
the base feature set of exec tracing can be useful.

To find all executables from /tmp

```shell-session
#  kubectl logs -n kube-system ds/tetragon -c export-stdout | jq 'select(.process_exec != null) | select(.process_exec.process.binary | contains("/tmp/")) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.pod.name) \(.process_exec.process.binary) \(.process_exec.process.arguments)"'
"2023-10-31T18:44:22.777962637Z default xwing /tmp/nc ebpf.io 1234"
```

## sudo Invocation Monitoring {#sudo}

No policy is required to monitor for execution of sudo. Execution tracing is
consider core functionality.

To find any sudo operatoins,

```shell-session
$ kubectl logs -n kube-system ds/tetragon -c export-stdout | jq 'select(.process_exec != null) | select(.process_exec.process.binary | contains("sudo")) | "\(.time) \(.process_exec.process.pod.namespace) \(.process_exec.process.binary) \(.process_exec.process.arguments)"'
"2023-10-31T19:03:35.273111185Z null /usr/bin/sudo -i"
```

Here we caught a user running sudo in the host platform indicated by the empty pod info.


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
