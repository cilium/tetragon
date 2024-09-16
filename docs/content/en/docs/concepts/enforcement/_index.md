---
title: "Enforcement"
weight: 4
description: "Documentation for Tetragon enforcement system"
---

Tetragon allows enforcing events in the kernel inline with the operation itself. This document
describes the types of enforcement provided by Tetragon and concerns policy implementors must be
aware of.

There are two ways that Tetragon performs enforcement: overriding the return value of a function and
sending a signal (e.g., `SIGKILL`) to the process.


## Override return value

Override the return value of a call means that the function will never be executed and, instead, a
value (typically an error) will be returned to the caller. Generally speaking, only system calls and
security check functions allow to change their return value in this manner. Details about how users
can configure tracing policies to override the return value can be found in the [Override
action]({{< ref "/docs/concepts/tracing-policy/selectors#override-action" >}}) documentation.

This behaviour can be disabled at the daemon level by setting the `--disable-override-actions` flag
which may be desirable to prevent privilage escalation via the gRPC API.

## Signals

Another type of enforcement is signals. For example, users can write a TracingPolicy (details can be
found in the [Signal action]({{<ref "/docs/concepts/tracing-policy/selectors#signal-action" >}})
documentation) that sends a `SIGKILL` to a process matching certain criteria and thus terminate it.

In contrast with overriding the return value, sending a `SIGKILL` signal does not always stop the
operation being performed by the process that triggered the operation. For example, a `SIGKILL` sent
in a `write()` system call does not guarantee that the data will not be written to the file.
However, it does ensure that the process is terminated synchronously (and any threads will be
stopped). In some cases it may be sufficient to ensure the process is stopped and the process does
not handle the return of the call. To ensure the operation is not completed, though, the `Signal`
action should be combined with the `Override` action.

This behaviour can be disabled at the daemon level by setting the `--disable-signal-actions` flag
which may be desirable to prevent privilage escalation via the gRPC API.
