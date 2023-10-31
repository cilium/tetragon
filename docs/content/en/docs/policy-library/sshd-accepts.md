---
title: "SSHd connection monitoring"
weight: 2
description: "Monitor network connections over SSHd"
---

This policy adds monitoring of all network connections accepted by SSHd to Tetragon.

To apply the policy use kubect apply,

```shell-session
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/acceptsshd.yaml
```

To find all sessions over SSHd,

```shell-session

```
