---
title: "Overview"
linkTitle: "Overview"
weight: 1
description: >
  Discover Tetragon and its capabilities
---

Cilium's new Tetragon component enables powerful realtime, eBPF-based Security
Observability and Runtime Enforcement.

Tetragon detects and is able to react to security-significant events, such as

* Process execution events
* System call activity
* I/O activity including network & file access

When used in a Kubernetes environment, Tetragon is Kubernetes-aware - that is,
it understands Kubernetes identities such as namespaces, pods and so-on - so
that security event detection can be configured in relation to individual
workloads.

{{< figure
    src="/images/smart_observability.png"
    caption="Tetragon Overview Diagram"
    width=800px
    alt="A diagram showing Tetragon capabilities and how it interacts with Kubernetes, the kernel and other metrics, logging, tracing or events systems"
>}}

## Functionality Overview

### eBPF Real-Time

Tetragon is a runtime security enforcement and observability tool. What this
means is Tetragon applies policy and filtering directly in eBPF in the kernel.
It performs the filtering, blocking, and reacting to events directly in the
kernel instead of sending events to a user space agent.

For an observability use case, applying filters directly in the kernel
drastically reduces observation overhead. By avoiding expensive context
switching and wake-ups, especially for high frequency events, such as send,
read, or write operations, eBPF reduces required resources. Instead, Tetragon
provides rich filters (file, socket, binary names, namespace/capabilities,
etc.) in eBPF, which allows users to specify the important and relevant events
in their specific context, and pass only those to the user-space agent.

### eBPF Flexibility ##

Tetragon can hook into any function in the Linux kernel and filter on its
arguments, return value, associated metadata that Tetragon collects about
processes (e.g., executable names), files, and other properties. By writing
tracing policies users can solve various security and observability use cases.
We provide a number of examples for these in the repository and highlight some
below in the 'Getting Started Guide', but users are encouraged to create new
policies that match their use cases. The examples are just that, jumping off
points that users can then use to create new and specific policy deployments
even potentially tracing kernel functions we did not consider. None of the
specifics about which functions are traced and what filters are applied are
hard-coded in the engine itself.

Critically, Tetragon allows hooking deep in the kernel where data structures
can not be manipulated by user space applications avoiding common issues with
syscall tracing where data is incorrectly read, maliciously altered by
attackers, or missing due to page faults and other user/kernel boundary errors.

Many of the Tetragon developers are also kernel developers. By leveraging this
knowledge base Tetragon has created a set of tracing policies that can solve
many common observability and security use cases.

### eBPF Kernel Aware ##

Tetragon, through eBPF, has access to the Linux kernel state. Tetragon can then
join this kernel state with Kubernetes awareness or user policy to create rules
enforced by the kernel in real time. This allows annotating and enforcing process
namespace and capabilities, sockets to processes, process file descriptor to
filenames and so on. For example, when an application changes its privileges we
can create a policy to trigger an alert or even kill the process before it has
a chance to complete the syscall and potentially run additional syscalls.

## What's next?

- [Getting Started](/docs/getting-started/): Get started with Tetragon.
- [Tetragon events](/docs/tetragon-events/): Learn about Tetragon events.

