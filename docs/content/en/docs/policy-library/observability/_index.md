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
the following, in this case checking std C library.

```shell-session

```

We can further restrict to only find versions before some number by adding
a versoin check.ontinue to explore the data set to learn interesting things here.

## Binary Execution in /tmp {#tmp-execs}

This policy adds monitoring of any executions in the /tmp directory.

For this we can simply query the default execution data showing even
the base feature set of exec tracing can be useful.

To find all executables from /tmp

```shell-session
# kubectl logs -n kube-system ds/tetragon -c export-stdout | jq 'select(.process_exec != null) | select(.process_exec.process.binary | contains("/tmp/")) | .process_exec.process |  "\(.binary) \(.pod.namespace) \(.pod.name)"'
"/tmp/nc default xwing"
"/tmp/nc default xwing"
"/tmp/nc default xwing"
"/tmp/nc default xwing"

```

## sudo Invocation Monitoring {#sudo}

This policy adds sudo monitoring to Tetragon.

To apply the policy use kubect apply,

```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/sudo.yaml
```

To find any sudo operatoins,

```shell-session

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
