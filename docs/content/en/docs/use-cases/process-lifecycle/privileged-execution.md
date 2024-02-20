---
title: "Privileged execution"
weight: 3
description: "Monitor process capabilities and kernel namespace access"
---

Tetragon also provides the ability to check process capabilities and kernel
namespaces access.

This information would help us determine which process or Kubernetes pod has
started or gained access to privileges or host namespaces that it should not
have. This would help us answer questions like:

> Which Kubernetes pods are running with `CAP_SYS_ADMIN` in my cluster?

> Which Kubernetes pods have host network or pid namespace access in my
> cluster?

## Step 1: Enabling Process Credential and Namespace Monitoring

* Edit the Tetragon configmap:

  ```bash
  kubectl edit cm -n kube-system tetragon-config
  ```

* Set the following flags from "false" to "true":

  ```bash
  # enable-process-cred: true
  # enable-process-ns: true
  ```

* Save your changes and exit.

* Restart the Tetragon daemonset:

  ```bash
  kubectl rollout restart -n kube-system ds/tetragon
  ```
## Step 2: Deploying a Privileged Nginx Pod

* Create a YAML file (e.g., privileged-nginx.yaml) with the following PodSpec:

  ```yaml
  apiVersion: v1
  kind: Pod
  metadata:
    name: privileged-the-pod
  spec:
    hostPID: true
    hostNetwork: true
    containers:
    - name: privileged-the-pod
      image: nginx:latest
      ports:
      - containerPort: 80
      securityContext:
        privileged: true
  ```

* Apply the configuration:

  ```bash
  kubectl apply -f privileged-nginx.yaml
  ```

## Step 3: Monitoring with Tetragon

* Start monitoring events from the privileged Nginx pod:

  ```bash
  kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents --namespace default --pod privileged-the-pod
  ```

* You should observe Tetragon generating events similar to these, indicating the privileged container start:

  ```bash
  🚀 process default/privileged-nginx /nginx -g daemon off;  🛑 CAP_SYS_ADMIN
  ```
  