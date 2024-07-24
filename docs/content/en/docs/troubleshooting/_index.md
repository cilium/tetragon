---
title: "Troubleshooting"
weight: 11
description: Learn how to troubleshoot Tetragon
aliases: ["/docs/tutorials/debugging-tetragon"]
---

## Automatic log and state collection

Before you report a problem, make sure to retrieve the necessary information
from your cluster.

Tetragon's bugtool captures potentially useful information about your
environment for debugging. The tool is meant to be used for debugging a single
Tetragon agent node but can be run automatically in a cluster. Note that in the
context of Kubernetes, the command needs to be run from inside the Tetragon
Pod's container.

Key information collected by bugtool:
- Tetragon configuration
- Network configuration
- Kernel configuration
- eBPF maps
- Process traces (if tracing is enabled)

### Automatic Kubernetes cluster sysdump

You can collect information in a Kubernetes cluster using the Cilium CLI:

```shell
cilium-cli sysdump
```

More details can be found in the [Cilium docs](https://docs.cilium.io/en/stable/operations/troubleshooting/#automatic-log-state-collection).
The Cilium CLI `sysdump` command will automatically run `tetra bugtool` on each
nodes where Tetragon is running.

### Manual single node sysdump

It's also possible to run the bug collection tool manually with the scope of a
single node using `tetra bugtool`.

#### Kubernetes installation

1. Identify the Tetragon Pod (`<tetragon-namespace>` is likely to be `kube-system`
   with the default install):

   ```bash
   kubectl get pods -n <tetragon-namespace> -l app.kubernetes.io/name=tetragon
   ```

2. Execute tetra bugtool within the Pod:

   ```bash
   kubectl exec -n <tetragon-namespace> <tetragon-pod-name> -c tetragon -- tetra bugtool
   ```

3. Retrieve the created archive from the Pod's filesystem:

   ```bash
   kubectl cp -c tetragon <tetragon-namespace>/<tetragon-pod-name>:tetragon-bugtool.tar.gz tetragon-bugtool.tar.gz
   ```

#### Container installation

1. Enter the Tetragon Container:

   ```bash
   docker exec -it <tetragon-container-id> tetra bugtool
   ```

2. Retrieve the archive using docker cp:

   ```bash
   docker cp <tetragon-container-id>:/tetragon-bugtool.tar.gz tetragon-bugtool.tar.gz
   ```

#### Systemd host installation

1. Execute tetra bugtool with Elevated Permissions:

   ```bash
   sudo tetra bugtool
   ```

## Enable debug log level

When debugging, it might be useful to change the log level. The default log
level is controlled by the log-level option at startup:

* Enable debug level with `--log-level=debug`
* Enable trace level with `--log-level=trace`

### Change log level on Kubernetes

{{< warning >}}
The Pods of the Tetragon DaemonSet will be restarted automatically after
changing the debug Helm value.
{{< /warning >}}

It is possible to change the log level of Tetragon's DaemonSet Pods by setting
`tetragon.debug` to `true`.

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

