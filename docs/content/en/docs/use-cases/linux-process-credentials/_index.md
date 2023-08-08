---
title: "Linux process credentials"
weight: 4
icon: "overview"
description: "Monitor Linux process credentials"
---

On Linux each process has various associated user, group IDs, capabilities,
secure management flags, keyring, LSM security that are used part of the
security checks upon acting on other objects. These are called the task
privileges or
[process credentials](https://www.kernel.org/doc/html/latest/security/credentials.html#task-credentials).

Changing the process credentials is a standard operation to perform privileged
actions or to execute commands as another user. The obvious example is
[sudo](https://www.sudo.ws/) that allows to gain high privileges and run commands
as root or another user. An other example is services or containers that can
gain high privileges during execution to perform restricted operations.

## Composition of Linux process credentials

### Traditional UNIX credentials

- Real User ID
- Real Group ID
- Effective, Saved and FS User ID
- Effective, Saved and FS Group ID
- Supplementary groups

### Linux Capabilities

- Set of permitted capabilities: a limiting superset for the effective
  capabilities.
- Set of inheritable capabilities: the set that may get passed across
  `execve(2)`.
- Set of effective capabilities: the set of capabilities a task is actually
  allowed to make use of itself.
- Set of bounding capabilities: limits the capabilities that may be inherited
  across `execve(2)`, especially when a binary is executed that will execute as
  UID 0.

### Secure management flags (securebits).

These govern the way the UIDs/GIDs and capabilities are manipulated and
inherited over certain operations such as `execve(2)`.

### Linux Security Module (LSM)

The [LSM framework](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html)
provides a mechanism for various security checks to be hooked by new kernel
extensions. Tasks can have extra controls part of LSM on what operations they
are allowed to perform.

## Tetragon Process Credentials monitoring

Monitoring Linux process credentials is a good practice to idenfity programs
running with high privileges. Tetragon allows retrieving Linux process credentials
as a [`process_credentials`]({{< ref "/docs/reference/grpc-api#processcredentials" >}}) object.

Changes to credentials can be monitored either in [system calls](/docs/use-cases/linux-process-credentials/syscalls-monitoring) or in [internal kernel functions](/docs/use-cases/linux-process-credentials/monitor-changes-at-kernel).

Generally it is better to monitor in internal kernel functions. For further details please read [Advantages and disadvantages of kernel layer monitoring compared to the system call layer](/docs/use-cases/linux-process-credentials/monitor-changes-at-kernel#advantages-and-disadvantages-of-kernel-layer-monitoring-compared-to-the-system-call-layer) section.
