---
title: "Use case: privileged execution"
weight: 2
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

As a first step let's enable visibility to capability and namespace changes via
the configmap by setting `enable-process-cred` and `enable-process-ns` from
`false` to `true`:
```bash
kubectl edit cm -n kube-system tetragon-config
# change "enable-process-cred" from "false" to "true"
# change "enable-process-ns" from "false" to "true"
# then save and exit
```
Restart the Tetragon daemonset:
```
kubectl rollout restart -n kube-system ds/tetragon
```

As a second step, let's start monitoring the Security Observability events from the privileged `test-pod` workload:
```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents --namespace default --pod test-pod
```

In another terminal let's apply the privileged PodSpec:
```bash
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/testdata/specs/testpod.yaml
```

If you observe the output in the first terminal, you can see the container start with `CAP_SYS_ADMIN`:
```bash
🚀 process default/test-pod /bin/sleep 365d                🛑 CAP_SYS_ADMIN
🚀 process default/test-pod /usr/bin/jq -r .bundle         🛑 CAP_SYS_ADMIN
🚀 process default/test-pod /usr/bin/cp /kind/product_name /kind/product_uuid /run/containerd/io.containerd.runtime.v2.task/k8s.io/7c7e513cd4d506417bc9d97dd9af670d94d9e84161c8c8 fdc9fa3a678289a59/rootfs/ 🛑 CAP_SYS_ADMIN
```
