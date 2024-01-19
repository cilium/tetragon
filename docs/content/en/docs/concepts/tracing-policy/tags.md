---
title: "Tags"
weight: 3
description: "Use Tags to categorize events"
---

Tags are optional fields of a Tracing Policy that are used to categorize
generated events.

## Introduction

Tags are specified in Tracing policies and will be part of the generated event.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring-filtered"
spec:
  kprobes:
  - call: "security_file_permission"
    message: "Sensitive file system write operation"
    syscall: false
    args:
    - index: 0
      type: "file" # (struct file *) used for getting the path
    - index: 1
      type: "int" # 0x04 is MAY_READ, 0x02 is MAY_WRITE
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/etc"              # Writes to sensitive directories
        - "/boot"
        - "/lib"
        - "/lib64"
        - "/bin"
        - "/usr/lib"
        - "/usr/local/lib"
        - "/usr/local/sbin"
        - "/usr/local/bin"
        - "/usr/bin"
        - "/usr/sbin"
        - "/var/log"          # Writes to logs
        - "/dev/log"
        - "/root/.ssh"        # Writes to sensitive files add here.
      - index: 1
        operator: "Equal"
        values:
        - "2" # MAY_WRITE
    tags: [ "observability.filesystem", "observability.process" ]
```

Every kprobe call can have up to max 16 tags.

## Namespaces

### Observability namespace

Events in this namespace relate to collect and export data about the internal system state.

* "observability.filesystem": the event is about file system operations.
* "observability.privilege_escalation": the event is about raising permissions of a user or a process.
* "observability.process": the event is about an instance of a Linux program being executed.

## User defined Tags

Users can define their own tags inside Tracing Policies. The official supported tags are documented
in the [Namespaces section](#namespaces).
