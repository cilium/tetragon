---
title: "Tags"
weight: 3
description: "Use Tags to categorize events"
---

Tags are optional fields of a Tracing Policy that are used to categorize
generated events.

## Introduction

Tags are specified in Tracing policies and will be part of the generated event.

{{< policy-example "file-monitoring/file-monitoring-filtered.yaml" >}}

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
