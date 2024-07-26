---
title: "Persistent enforcement"
weight: 2
description: "How to configure persistent enforcement"
---

This page shows you how to configure persistent enforcement.

## Concept

The idea of persistent enforcement is to allow he enforcement policy to continue
running even when its tetragon process is gone.

This is configured with `--keep-sensors-on-exit` option.

When the tetragon process exits the policy stays active, because it's pinned
in sysfs bpf tree under `/sys/fs/bpf/tetragon` directory.

When new tetragon process is started it performs following actions:

- checks if there's existing `/sys/fs/bpf/tetragon` and moves it to `/sys/fs/bpf/tetragon_old` directory
- setups configured policy
- removes `/sys/fs/bpf/tetragon_old` directory.

## Example

This example shows how the persistent enforcement works on simple tracing policy.

- Consider following enforcement tracing policy that kills any process that touches `/tmp/tetragon` file.

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

- Spawn tetragon with above policy and `--keep-sensors-on-exit` option.

```
# tetragon ... --keep-sensors-on-exit
```

- Verify the enforcement policy is in place.

```
$ cat /tmp/tetragon
Killed
```

- Kill tetragon

```
time="2024-07-26T14:47:45Z" level=info msg="Perf ring buffer size (bytes)" percpu=68K total=272K
time="2024-07-26T14:47:45Z" level=info msg="Perf ring buffer events queue size (events)" size=63K
time="2024-07-26T14:47:45Z" level=info msg="Listening for events..."
^C
time="2024-07-26T14:50:50Z" level=info msg="Received signal interrupt, shutting down..."
time="2024-07-26T14:50:50Z" level=info msg="Listening for events completed." error="context canceled"
```

- Verify the enforcement policy is **STILL** in place.

```
$ cat /tmp/tetragon
Killed
```

##  Limitations

At the moment we are not able to receive any events during the tetragon down time,
it's just the enforcement that's in place.
