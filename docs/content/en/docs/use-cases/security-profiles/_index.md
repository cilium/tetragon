---
title: "Security Profiles"
weight: 5
icon: "overview"
description: "Observe and record security events"
---

Tetragon is able to observe various security events and even enforce security
policies.

The [Record Linux Capabilities Usage]({{< ref "/docs/use-cases/security-profiles/record-linux-capabilities" >}}) guide
shows how to monitor and record [Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) checks
conducted by the kernel on behalf of applications during privileged operations. This can be used to inspect
and produce security profiles for pods and containers.
