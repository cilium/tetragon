---
title: "Network Access Monitoring"
weight: 2
description: "Network Access Traces with Tetragon"
---

This adds a network policy on top of execution and file tracing
already deployed in the quick start. In this case we monitor
all network traffic outside the Kubernetes CIDR.

To apply the policy

{{< tabpane lang=shell-session >}}

{{< tab Kubernetes >}}
kubectl apply -f tbd.network.yaml
{{< /tab >}}

{{< tab Docker >}}
{{< /tab >}}

{{< tab Systemd >}}
{{< /tab >}}

{{< /tabpane >}}

With the file applied we can attach tetra to observe events again,

```shell-session
 kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon
```

And once again execute a curl command in the xwing,

```shell-session
 kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon
```

The CLI will print the exec tracing and file access as before, but will additional show the network connection outside the K8s cluster.

#
