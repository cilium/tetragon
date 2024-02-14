---
title: "Troubleshooting"
weight: 11
description: Learn how to troubleshoot Tetragon
aliases: ["/docs/tutorials/debugging-tetragon"]
---

## Automatic log and state collection

Before you report a problem, make sure to retrieve the necessary information from your cluster.

### Kubernetes cluster

You collect information in a Kubernetes cluster using the Cilium CLI:

```shell
cilium-cli sysdump
```

More details can be found in the [Cilium docs](https://docs.cilium.io/en/stable/operations/troubleshooting/#automatic-log-state-collection).

### Single Node bugtool

If you are not running Kubernetes, it is also possible to run the bug collection tool manually with the scope of a single node using:

```shell
tetra bugtool
```

Tetragon's bugtool captures potentially useful information about your
environment for debugging. The tool is meant to be used for debugging a single
Tetragon agent node. Note that in the context of Kubernetes, the command needs
to be run from inside the Tetragon Pod's container.

## Enable debug log level

When debugging, it might be useful to change the log level. The default log
level is controlled by the log-level option at startup:

* Enable debug level with `--log-level=debug`
* Enable trace level with `--log-level=trace`

### Change log level dynamically

It is possible to change the log level dynamically by sending the corresponding
signal to tetragon process.

* Change log level to debug level by sending the `SIGRTMIN+20` signal to tetragon pid:

  ```shell
  sudo kill -s SIGRTMIN+20 $(pidof tetragon)
  ```

* Change log level to trace level by sending the `SIGRTMIN+21` signal to tetragon pid:

  ```shell
  sudo kill -s SIGRTMIN+21 $(pidof tetragon)
  ```

* To Restore the original log level send the `SIGRTMIN+22` signal to tetragon pid:

  ```shell
  sudo kill -s SIGRTMIN+22 $(pidof tetragon)
  ```

