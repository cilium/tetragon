---
title: "Use Cases"
icon: "resources"
weight: 4
description: >
  This section presents various use cases on process, files, network and
  security monitoring and enforcement.
---

By default, Tetragon monitors process lifecycle, learn more about that in the
[dedicated use cases]({{< ref "/docs/use-cases/process-lifecycle/" >}}).

For more advanced use cases, Tetragon can observe tracepoints and arbitrary
kernel calls via kprobes. For that, Tetragon must be extended and configured
with custom resources objects named [TracingPolicy]({{< ref "/docs/concepts/tracing-policy" >}}).
It can then generates `process_tracepoint` and `process_kprobes` events.

