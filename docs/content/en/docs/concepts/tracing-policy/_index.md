---
title: "Tracing Policy"
weight: 2
description: "Documentation for the TracingPolicy custom resource"
---

Tetragon's `TracingPolicy` is a user-configurable Kubernetes custom resource (CR) that
allows users to trace arbitrary events in the kernel and optionally define
actions to take on a match. Policies consist of a hook point (kprobes,
tracepoints, and uprobes are supported), and selectors for in-kernel filtering
and specifying actions. For more details, see
[hook points page]({{< ref "/docs/concepts/tracing-policy/hooks" >}}) and the
[selectors page]({{< ref "/docs/concepts/tracing-policy/selectors" >}}).

{{< caution >}}
`TracingPolicy` allows for powerful, yet low-level configuration and, as such,
requires knowledge about the Linux kernel and containers to avoid unexpected
issues such as TOCTOU bugs.
{{< /caution >}}

For the complete custom resource definition (CRD) refer to the YAML file
[`cilium.io_tracingpolicies.yaml`](https://github.com/cilium/tetragon/blob/main/pkg/k8s/apis/cilium.io/client/crds/v1alpha1/cilium.io_tracingpolicies.yaml).
One practical way to explore the CRD is to use `kubectl explain` against a
Kubernetes API server on which it is installed, for example `kubectl explain
tracingpolicy.spec.kprobes` provides field-specific documentation and details
on kprobe spec.

Tracing Policies can be loaded and unloaded at runtime in Tetragon, or on
startup using flags.
- With Kubernetes, you can use `kubectl` to add and remove a `TracingPolicy`.
- You can use `tetra` gRPC CLI to add and remove a `TracingPolicy`.
- You can use the `--tracing-policy` and `--tracing-policy-dir` flags to statically add policies at
  startup time, see more in the [daemon configuration page]({{< ref
  "/docs/reference/daemon-configuration#configure-tracing-policies-location" >}}).


Hence, even though Tracing Policies are structured as a Kubernetes CR, they can also be used in
non-Kubernetes environments using the last two loading methods.
