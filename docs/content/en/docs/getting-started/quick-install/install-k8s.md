---
title: "Try Tetragon on Kubernetes"
weight: 1
description: "Discover and experiment with Tetragon in a kubernetes environment"
---

### Create a cluster

If you don’t have a Kubernetes Cluster yet, you can use the instructions below to create a Kubernetes cluster locally or using a managed Kubernetes service:

TBD tabplane this...

#### Kind

Run the following command to create the Kubernetes cluster:
```
kind create cluster
```

{{< tabpane text=true >}}
{{% tab GKE %}}

The following commands create a Kubernetes cluster using [Google
Kubernetes Engine](https://cloud.google.com/kubernetes-engine). See
[Installing Google Cloud SDK](https://cloud.google.com/sdk/install) for
instructions on how to install `gcloud` and prepare your account.

Create the node pool with the following taint to guarantee that Pods are only
scheduled/executed in the node when Cilium is ready. Alternatively, see the
note below.

```shell-session
export NAME="$(whoami)-$RANDOM"
gcloud container clusters create "${NAME}" \
 --node-taints node.cilium.io/agent-not-ready=true:NoExecute \
 --zone us-west2-a
gcloud container clusters get-credentials "${NAME}" --zone us-west2-a
```

{{% /tab %}}
{{< /tabpane >}}

#### GKE

Run the following command to create a GKE cluster:

```shell
export NAME="$(whoami)-$RANDOM"
gcloud container clusters create "${NAME}" \
  --zone us-west2-a \
  --num-nodes 1
```

### Deploy Tetragon

To install and deploy Tetragon, run the following commands:

```shell
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon -w
```

By default, Tetragon will filter kube-system events to reduce noise in the
event logs. See concepts and advanced configuration to configure these
parameters.

### Deploy demo application

To explore Tetragon its helpful to have a sample workload. Here wu use the Cilium
HTTP application, but any workload would work equally well.

To use our [demo
application](https://docs.cilium.io/en/v1.11/gettingstarted/http/#deploy-the-demo-application)

```shell
kubectl create -f https://raw.githubusercontent.com/cilium/cilium/v1.11/examples/minikube/http-sw-app.yaml
```

Before going forward, verify that all pods are up and running - it might take
several seconds for some pods until they satisfy all the dependencies:

```shell
kubectl get pods
```

The output should be similar to:
```
NAME                         READY   STATUS    RESTARTS   AGE
deathstar-6c94dcc57b-7pr8c   1/1     Running   0          10s
deathstar-6c94dcc57b-px2vw   1/1     Running   0          10s
tiefighter                   1/1     Running   0          10s
xwing                        1/1     Running   0          10s
```


