---
title: "Host System Changes"
weight: 5
icon: "overview"
description: "Monitor Host System changes"
---

Some pods need to change the host system or kernel parameters in order to
perform administrative tasks, obvious examples are pods loading a kernel
module to extend the operating system functionality, or pods managing the
network.

However, there are also other cases where a compromised container may want to
load a kernel module to hide its behaviour.

In this aspect, monitoring such host system changes helps to identify pods
and containers that affect the host system.

## Monitor Linux kernel modules

A kernel module is a code that can be loaded into the kernel image at runtime,
without rebooting. These modules, which can be loaded by pods and containers,
can modify the host system. The
[Monitor Linux kernel modules]({{< ref "/docs/use-cases/host-system-changes/linux-kernel-modules" >}})
guide will assist you in observing such events.
