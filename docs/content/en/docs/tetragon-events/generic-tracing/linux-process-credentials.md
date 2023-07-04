---
title: "Monitor Linux Process Credentials"
weight: 1
icon: "overview"
description: "Monitor Linux Process Credentials"
---

On Linux each process has various associated user, group IDs, capabilities,
secure management flags, keyring, LSM security that are used part of the
security checks upon acting on other objects. These are called the task
privileges or
[process credentials](https://www.kernel.org/doc/html/next/security/credentials.html#task-credentials).

Changing the process credentials is a standard operation to perform privileged
actions or to execute commands as another user. The obvious example is
[sudo](https://www.sudo.ws/) that allows to gain high privileges and run commands
as root or another user. An other example is services or containers that can
gain high privileges during execution to perform restricted operations.

Monitoring process credentials is good practice to identify programs
running with high privileges. Tetragon is able to observe process credentials at different layers of the OS.
Each layer will generate a number of events, where the upper layer that is the user space layer will generate a low number of events, where the lower kernel layers could generate a high number of events.


Monitoring process credentials can be performed at different layers.
Each layer will generate a number of events, these layers are ordered
from low to high where high means a high number of events as the monitoring happens at kernel space.

Users should chose the right layer at which they want to monitor process credentials and apply the corresponding Tracing Policies.

### Layer 1 User space command execution

At this layer we monitor execution of commands that allow to alter
the process credentials.

{{< note >}}
Number of generated events: Low.

The monitoring at this layer happens at process execution and will generate a ["process_exec"](https://tetragon.cilium.io/docs/reference/grpc-api/#processexec) event.
{{< /note >}}

Example of commands to monitor:

    su   
    sudo


TODO add example


### Layer 2 System call monitoring

{{< note >}}
Number of generated events: Medium.

The monitoring at this layer happens around the system call layer and will generate a ["process_kprobe"](https://tetragon.cilium.io/docs/reference/grpc-api/#processkprobe) event.
{{< /note >}}

TODO add example

### Layer 3 Credentials checks

TODO add example

### Layer 4 Credentials changes

TODO add example
