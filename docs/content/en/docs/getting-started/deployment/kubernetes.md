---
title: "Deploy on Kubernetes"
weight: 1
description: "Deploy and manage Tetragon on Kubernetes"
---

The recommended way to deploy Tetragon on a Kubernetes cluster is to use the
Helm chart with Helm 3. Tetragon uses the [helm.cilium.io](https://helm.cilium.io)
repository to release the helm chart.

## Install

To install the latest release of the Tetragon helm chart, use the following
command.

{{< note >}}
You can find the chart and its documentation with all availabe values for
configuration in [install/kubernetes](https://github.com/cilium/tetragon/tree/main/install/kubernetes)
in the Tetragon repository. You can use any of the value and override them with
`--set KEY1=VALUE1,KEY2=VALUE2`.
{{< /note >}}

```shell
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
```

To wait until Tetragon deployment is ready, use the following `kubectl` command:
```shell
kubectl rollout status -n kube-system ds/tetragon -w
```

{{< note >}}
By default, pods in the kube-system namespace are filtered-out.
{{< /note >}}

## Configuration

You can then make modifications to the Tetragon configuration using `helm
upgrade`, see the following example.

```shell
helm upgrade tetragon cilium/tetragon -n kube-system --set tetragon.grpc.address=localhost:1337
```

You can also edit the `tetragon-config` ConfigMap directly and restart the
Tetragon daemonset with:

```shell
kubectl edit cm tetragon-config -n kube-system
kubectl rollout restart ds/tetragon -n kube-system
```

## Upgrade

Upgrade Tetragon using a new specific version of the helm chart.

```shell
helm upgrade tetragon cilium/tetragon -n kube-system --version 0.9.0
```

## Uninstall

Uninstall Tetragon using the following command.

```shell
helm uninstall tetragon -n kube-system
```
