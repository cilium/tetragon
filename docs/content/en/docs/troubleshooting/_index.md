---
title: "Troubleshooting"
weight: 11
description: Troubleshooting Tetragon
---

## Reporting a problem

Before you report a problem, make sure to retrieve the necessary information from your cluster.

### Automatic log & state collection

You collect information in a Kubernetes cluster using the Cilium CLI:

```shell
cilium-cli sysdump
```

More details can be found in the [Cilium docs](https://docs.cilium.io/en/stable/operations/troubleshooting/#automatic-log-state-collection).

### Single Node Bugtool

If you are not running Kubernetes, it is also possible to run the bug collection tool manually with the scope of a single node using:

```shell
tetra bugtool
```

Tetragon's bugtool captures potentially useful information about your environment for debugging. The tool is meant to be used for debugging a single Tetragon agent node. Note in Kubernetes, the command needs to be run from inside the Tetragon pod/container.

