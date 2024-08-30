---
title: "Runtime Hooks"
weight: 3
description: "Tetragon Runtime Hooks"
---

Applying
[Kubernetes Identity Aware Policies]({{< ref "/docs/concepts/tracing-policy/k8s-filtering/" >}})
requires information about Kubernetes (K8s) pods (e.g., namespaces and labels). Based on this
information, the Tetragon agent can update the state so that Kubernetes Identify filtering can be
applied in-kernel via BPF.

One way that this information is available to the Tetragon agent is via the K8s API server. Relying
on the API server, however, can lead to a delay before the container starts and the policy is
applied. This might be undesirable, especially for enforcement policies.

Runtime hooks address this issue by "hooking" into the container run-time system, and ensuring that
the Tetragon agent sets up the necessary state for filtering before the container starts.


The OCI hooks are implemented via a `tetragon-oci-hook` binary which is responsible for contacting
the agent via a gRPC socket. `tetragon-oci-hook` can be configured to either fail or succeed when
connecting to the tetragon agent fails (this is needed, so that Tetragon itself, as well as other
mission critical containers can be started).

```
┌────────────────────┐         ┌────────────────────┐        ┌──────────────────┐
│  tetragon-oci-hook │         │   tetragon.sock    │        │  tetragon agent  │
│    (binary)        │─────────┤ (gRPC UNIX socket) │──────► │                  │
│                    │         │                    │        │                  │
└────────────────────┘         └────────────────────┘        └──────────────────┘
```


Depending on the container runtime, there are different ways to configure the runtime so that
`tetragon-oci-hook` is executed before a container starts:

## CRI-O

CRI-O implements the OCI hooks configuration directories as described in:
https://github.com/containers/common/blob/main/pkg/hooks/docs/oci-hooks.5.md.
Hence, enabling the hook requires adding an appropriate file to this directory.

## Containerd (with NRI)

Recent versions of containerd support [NRI](https://github.com/containerd/nri): NRI support was
added in [1.7](https://github.com/containerd/containerd/releases/tag/v1.7.0) and will be enabled by
default starting with
[2.0](https://github.com/containerd/containerd/blob/main/docs/NRI.md#disabling-nri-support-in-containerd).
To use `tetragon-oci-hook` with NRI, there is a simple NRI plugin (called `tetragon-nri-hook`) that
adds the `tetragon-oci-hook` to the container spec.

## Containerd (without NRI)

Containerd can be configured to use a custom container spec that includes `tetragon-oci-hook`.

## Configuration

See [Configure Runtime Hooks]({{< ref "/docs/installation/runtime-hooks.md" >}}).
