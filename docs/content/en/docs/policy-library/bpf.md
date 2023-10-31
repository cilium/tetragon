---
title: "BPF monitoring"
weight: 2
description: "Monitor BPF program and file operations on BPFFS"
---

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
