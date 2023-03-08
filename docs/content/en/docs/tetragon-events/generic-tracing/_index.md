---
title: "Generic tracing"
weight: 2
description: "Tetragon can observe tracepoints and arbitrary kernel calls via kprobes"
---

For more advanced use cases, Tetragon can observe tracepoints and arbitrary
kernel calls via kprobes. For that, Tetragon must be extended and configured
with custom resources objects named TracingPolicy. It can then generates
`process_tracepoint` and `process_kprobes` events.

TracingPolicy is a user-configurable Kubernetes custom resource that allows
users to trace arbitrary events in the kernel and optionally define actions to
take on a match. For example, a Sigkill signal can be sent to the process or
the return value of a system call can be overridden.

For bare metal or VM use cases without Kubernetes, the same YAML configuration
can be passed via the `--config-file` flag to the Tetragon binary or via the
`tetra` CLI to load the policies via gRPC.

## What's next

For more information on TracingPolicy and how to write them, see the
[reference documentation on TracingPolicy](/docs/reference/tracing-policy/).

