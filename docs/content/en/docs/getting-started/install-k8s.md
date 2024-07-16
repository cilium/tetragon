---
title: "Quick Kubernetes Install"
weight: 1
description: "Discover and experiment with Tetragon in a kubernetes environment"
---

### Create a cluster

If you don’t have a Kubernetes Cluster yet, you can use the instructions below
to create a Kubernetes cluster locally or using a managed Kubernetes service:

{{< tabpane text=true >}}
{{% tab GKE %}}

The following commands create a single node Kubernetes cluster using [Google
Kubernetes Engine](https://cloud.google.com/kubernetes-engine). See
[Installing Google Cloud SDK](https://cloud.google.com/sdk/install) for
instructions on how to install `gcloud` and prepare your account.

```shell
export NAME="$(whoami)-$RANDOM"
export ZONE="us-west2-a"
gcloud container clusters create "${NAME}" --zone ${ZONE} --num-nodes=1
gcloud container clusters get-credentials "${NAME}" --zone ${ZONE}
```
{{% /tab %}}
{{% tab AKS %}}

The following commands create a single node Kubernetes cluster using [Azure
Kubernetes Service](https://docs.microsoft.com/en-us/azure/aks/). See
[Azure Cloud CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)
for instructions on how to install `az` and prepare your account.

```shell
export NAME="$(whoami)-$RANDOM"
export AZURE_RESOURCE_GROUP="${NAME}-group"
az group create --name "${AZURE_RESOURCE_GROUP}" -l westus2
az aks create --resource-group "${AZURE_RESOURCE_GROUP}" --name "${NAME}"
az aks get-credentials --resource-group "${AZURE_RESOURCE_GROUP}" --name "${NAME}"
```
{{% /tab %}}
{{% tab EKS %}}

The following commands create a single node Kubernetes cluster with `eksctl` using [Amazon Elastic
Kubernetes Service](https://aws.amazon.com/eks/). See [eksctl installation](https://github.com/eksctl-io/eksctl#installation)
for instructions on how to install `eksctl` and prepare your account.

```shell
export NAME="$(whoami)-$RANDOM"
eksctl create cluster --name "${NAME}"
```
{{% /tab %}}

{{% tab "Kind" %}}

Tetragon's correct operation depends on access to the host `/proc` filesystem. The following steps
configure kind and Tetragon accordingly when using a Linux system. The following commands create a single node Kubernetes cluster using `kind` that is properly configured for Tetragon.

```shell
cat <<EOF > kind-config.yaml
apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: /proc
        containerPath: /procHost
EOF
kind create cluster --config kind-config.yaml
EXTRA_HELM_FLAGS=(--set tetragon.hostProcPath=/procHost) # flags for helm install
```
{{% /tab %}}

{{< /tabpane >}}

The commands in this Getting Started guide assume you use a single-node
Kubernetes cluster. If you use a cluster with multiple nodes, be aware that
some of the commands shown need to be modified. We call out these changes where
they are necessary.

### Deploy Tetragon

To install and deploy Tetragon, run the following commands:

```shell
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon ${EXTRA_HELM_FLAGS[@]} cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon -w
```

By default, Tetragon will filter kube-system events to reduce noise in the
event logs. See concepts and advanced configuration to configure these
parameters.

### Deploy demo application

To explore Tetragon it is helpful to have a sample workload. Here we use Cilium's
[demo application](https://docs.cilium.io/en/stable/gettingstarted/demo/),
but any workload would work equally well:

```shell
kubectl create -f {{< demo-app-url >}}
```

Before going forward, verify that all pods are up and running - it might take
several seconds for some pods to satisfy all the dependencies:

```shell
kubectl get pods
```

The output should be similar to this:

```
NAME                         READY   STATUS    RESTARTS   AGE
deathstar-6c94dcc57b-7pr8c   1/1     Running   0          10s
deathstar-6c94dcc57b-px2vw   1/1     Running   0          10s
tiefighter                   1/1     Running   0          10s
xwing                        1/1     Running   0          10s
```

## What's Next

Check for [execution events]({{< ref "/docs/getting-started/execution" >}}).
