---
title: "Enforcement"
icon: "overview"
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

## Signals

Another type of enforcement is signals. For example, users can write a TracingPolicy (details can be
found in the [Signal action]({{<ref "/docs/concepts/tracing-policy/selectors#signal-action" >}})
documentation) that sends a `SIGKILL` to a process matching certain criteria and thus terminate it.
In contrast with overriding the return value, sending a signal does not always stop the operation
performed by the process from being executed.  For example, a `SIGKILL` might be send in a `write()`
system call does not guarantee that the data will not be written to the file.
