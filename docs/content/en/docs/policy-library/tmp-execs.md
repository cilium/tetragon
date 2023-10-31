---
title: "Tmp binary"
weight: 2
description: "Monitor executions from /tmp directory"
---

This policy adds monitoring of any executions in the /tmp directory.

For this we can simply query the default execution data showing even
the base feature set of exec tracing can be useful.

To find all executables from /tmp

```shell-session
# kubectl logs -n kube-system ds/tetragon -c export-stdout | jq 'select(.process_exec != null) | select(.process_exec.process.binary | contains("/tmp/")) | .process_exec.process |  "\(.binary) \(.pod.namespace) \(.pod.name)"'
"/tmp/nc default xwing"
"/tmp/nc default xwing"
"/tmp/nc default xwing"
"/tmp/nc default xwing"

```
