---
title: "Enforcement Mode"
weight: 5
description: "Configuring enforcement in tracing policies"
---

Beyond monitoring, Tetragon tracing policies include [enforcement]({{< ref "/docs/concepts/enforcement" >}}) actions.
Configuring the mode of a policy allows you to disable enforcement in a policy, without modifying
the policy itself.

A tracing policy can be set in two modes:
 - `monitoring`: enforcement operations are elided
 - `enforcement`: enforcement operations are respected and performed

Using the `tetra` CLI, you can inspect the mode of each policy.
For example:

```shell
tetra tracingpolicy list
```

Will produce out similar to:
```
ID   NAME               STATE     FILTERID   NAMESPACE   SENSORS              KERNELMEMORY   MODE
1    enforce-security   enabled   1          pizza       generic_kprobe       7.53 MB        enforce
2    allsyscalls        enabled   0          (global)    generic_tracepoint   4.25 MB        monitor
```

There are three ways that a policy mode can be set. From lower to higher priority, they are:

1. Setting the mode in the policy itself
2. Setting the mode when loading the policy
3. Setting the mode at runtime (via gRPC)

## Setting the mode in the policy itself

The policy mode can be set in the `spec.options` field, under the `policy-mode` key.
For example:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: "enforce-policy"
  namespace: "default"
spec:
  options:
    - name: "policy-mode"
      value: "monitor"
   ...
```

## Setting the mode when loading the policy

This can be done via the `tetra` CLI:

```shell
tetra tracingpolicy add --mode monitor policy.yaml
```

Will load `policy.yaml` in _monitor_ mode.

## Setting the policy at runtime

You can use the `tetra` CLI to set the policy mode once the policy is loaded.
For example:

```shell
tetra tp set-mode --namespace pizza enforce-security enforce
```
