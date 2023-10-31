---
title: "Library version monitoring"
weight: 2
description: "Monitor library loads for out of date openssl library"
---

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
a versoin check.
