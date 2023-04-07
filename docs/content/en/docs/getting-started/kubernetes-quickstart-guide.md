---
title: "Kubernetes quickstart guide"
weight: 2
description: "Deploy Tetragon on a Kubernetes cluster"
---

This quickstart guide uses a Kind cluster and a helm-based installation to
provide a simple way to get a hands on experience with Tetragon and
the generated events. These events include monitoring process execution,
network sockets, and file access to see what binaries are executing and making
network connections or writing to sensitive files.

In this scenario, we are going to install a demo application,

* observe all process execution happening inside a Kubernetes workload
* detect file access and writes
* observe network connections that a Kubernetes workload is making
* detect privileged processes inside a Kubernetes workload

While, we use a Kubernetes Kind cluster in this guide, users can also apply
the same concepts in other Kubernetes platforms, bare-metal, or VM environments.

### Requirements

The base kernel should support [BTF](#btf-requirement) or the BTF file should
be placed where Tetragon can read it.

For reference, the examples below use this [Vagrantfile](#btf-requirement) and we
created our [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/) cluster using
the defaults options.

### Create a cluster

Create a Kubernetes cluster using Kind or GKE.

#### Kind

Run the following command to create the Kubernetes cluster:
```
kind create cluster
```

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

By default, kube-system pods are filtered. For the examples below, we use the demo
deployment from [Cilium](https://docs.cilium.io/en/v1.11/gettingstarted/http/#gs-http)
to generate events.

### Deploy the demo application

Once Tetragon is installed, you can use our [demo
application](https://docs.cilium.io/en/v1.11/gettingstarted/http/#deploy-the-demo-application)
to explore the Security Observability Events:

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

### What's next

Learn how to checks this events in the next section [Explore security
observability events](/docs/getting-started/explore-security-observability-events).
