---
title: "Enforcement Mode"
weight: 5
description: "Configuring enforcement in tracing policies"
---

Beyond monitoring, Tetragon tracing policies include [enforcement]({{< ref "/docs/concepts/enforcement" >}}) actions.
Configuring the mode of a policy allows you to disable enforcement in a policy, without modifying
the policy itself.

A tracing policy can be set in three modes:
 - `monitoring`: enforcement operations are elided
 - `enforcement`: enforcement operations are respected and performed
 - `monitor_only`: the policy has no enforcement actions, thus it cannot be set to `enforcement` mode

Using the `tetra` CLI, you can inspect the mode of each policy.
For example:

```shell
tetra tracingpolicy list
```

Will produce out similar to:
```
ID   NAME                  DOMAIN   STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE           NPOST   NENFORCE   NMONITOR
2    trace-bash-readline   static   enabled   0          (global)    generic_uprobe   2.40 MB        monitor_only   5       0          0
3    read-etc-passwd       grpc     enabled   0          (global)    generic_kprobe   1.88 MB        monitor_only   33      0          0
```

There are three ways that a policy mode can be set. From lower to higher priority, they are:

1. Setting the mode in the policy itself
2. Setting the mode when loading the policy
3. Setting the mode at runtime (via gRPC)

Trying to set the mode at runtime for a `monitor_only` policy will result in an error.
Loading it will always succeed, even with a `mode` specified. In that case, a warning will be logged.

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
