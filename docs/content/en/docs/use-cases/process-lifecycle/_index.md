---
title: "Process lifecycle"
linkTitle: "Process lifecyle"
weight: 1
description: "Tetragon observes by default the process lifecycle via exec and exit"
---

Tetragon observes process creation and termination with default configuration
and generates `process_exec` and `process_exit` events:

- The `process_exec` events include useful information about the execution of
  binaries and related process information. This includes the binary image that
  was executed, command-line arguments, the UID context the process was
  executed with, the process parent information, the capabilities that a
  process had while executed, the process start time, the Kubernetes Pod,
  labels and more.
- The `process_exit` events, as the `process_exec` event shows how and when a
  process started, indicate how and when a process is removed. The information
  in the event includes the binary image that was executed, command-line
  arguments, the UID context the process was executed with, process parent
  information, process start time, the status codes and signals on process
  exit. Understanding why a process exited and with what status code helps
  understand the specifics of that exit.

Both these events include Linux-level metadata (UID, parents, capabilities,
start time, etc.) but also Kubernetes-level metadata (Kubernetes namespace,
labels, name, etc.). This data make the connection between node-level concepts,
the processes, and Kubernetes or container environments.

These events enable a full lifecycle view into a process that can aid an
incident investigation, for example, we can determine if a suspicious process
is still running in a particular environment. For concrete examples of such
events, see the next use case on process execution.

