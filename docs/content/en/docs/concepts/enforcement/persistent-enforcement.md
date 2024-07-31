---
title: "Persistent enforcement"
weight: 1
description: "How to configure persistent enforcement"
---

This page shows you how to configure persistent enforcement.

## Concept

The idea of persistent enforcement is to allow the enforcement policy to continue
running even when its tetragon process is gone.

This is configured with the `--keep-sensors-on-exit` option.

When the tetragon process exits, the policy stays active because it's pinned
in sysfs bpf tree under `/sys/fs/bpf/tetragon` directory.

When a new tetragon process is started, it performs the following actions:

- checks if there's existing `/sys/fs/bpf/tetragon` and moves it to
  `/sys/fs/bpf/tetragon_old` directory;
- sets up configured policy;
- removes `/sys/fs/bpf/tetragon_old` directory.

## Example

This example shows how the persistent enforcement works on simple tracing policy.

1. Consider the following enforcement tracing policy that kills any process that touches `/tmp/tetragon` file.

   ```yaml
   apiVersion: cilium.io/v1alpha1
   kind: TracingPolicy
   metadata:
    name: "enforcement"
   spec:
    kprobes:
    - call: "fd_install"
      syscall: false
      args:
      - index: 0
        type: int
      - index: 1
        type: "file"
      selectors:
      - matchArgs:
        - index: 1
          operator: "Equal"
          values:
          - "/tmp/tetragon"
        matchActions:
        - action: Sigkill
   ```

1. Spawn tetragon with the above policy and `--keep-sensors-on-exit` option.

   ```shell
   tetragon --bpf-lib bpf/objs/ --keep-sensors-on-exit --tracing-policy enforcement.yaml
   ```

1. Verify that the enforcement policy is in place.

   ```shell
   cat /tmp/tetragon
   ```

   The output should be similar to

   ```
   Killed
   ```

1. Kill tetragon with <kbd>CTRL+C</kbd>.

   ```
   time="2024-07-26T14:47:45Z" level=info msg="Perf ring buffer size (bytes)" percpu=68K total=272K
   time="2024-07-26T14:47:45Z" level=info msg="Perf ring buffer events queue size (events)" size=63K
   time="2024-07-26T14:47:45Z" level=info msg="Listening for events..."
   ^C
   time="2024-07-26T14:50:50Z" level=info msg="Received signal interrupt, shutting down..."
   time="2024-07-26T14:50:50Z" level=info msg="Listening for events completed." error="context canceled"
   ```

1. Verify that the enforcement policy is **STILL** in place.

   ```shell
   cat /tmp/tetragon
   ```

   The output should be still similar to

   ```
   Killed
   ```

##  Limitations

At the moment we are not able to receive any events during the tetragon down time,
only the the enforcement is in place.
