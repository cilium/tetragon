---
title: "Configure Runtime Hooks"
linkTitle: "Runtime Hooks"
weight: 3
description: "Configure Runtime Hooks"
---

See [Tetragon Rutime Hooks]({{< ref "/docs/concepts/runtime-hooks" >}}), for an introduction to
the topic.

We use `minikube` as the example platform because it supports both `cri-o` and `containerd`. Also,
at the time of this writing, no images that support this have been released, so we build images
locally within a checked out repo.

```shell
make image image-operator image-rthooks
```

## CRI-O

### Setup Minikube

```shell
minikube start --driver=kvm2 --container-runtime=cri-o
minikube image load cilium/tetragon:latest
minikube image load cilium/tetragon-operator:latest
minikube image load cilium/tetragon-rthooks:latest
minikube image ls | grep tetragon
```

The output should be similar to:

```
localhost/cilium/tetragon:latest
localhost/cilium/tetragon-rthooks:latest
localhost/cilium/tetragon-operator:latest
```
### Install Tetragon

```shell
helm install \
   --namespace kube-system \
   --set tetragon.image.override=localhost/cilium/tetragon:latest \
   --set tetragonOperator.image.override=localhost/cilium/tetragon-operator:latest \
   --set rthooks.enabled=true \
   --set rthooks.interface=oci-hooks \
   --set rthooks.image.override=localhost/cilium/tetragon-rthooks:latest \
   tetragon ./install/kubernetes/tetragon
```


```shel
kubecl -n kube-system get pods | grep tetragon
```

With output similar to:
```
tetragon-hpjwq                       2/2     Running   0          2m42s
tetragon-operator-664ddc8957-9lmd2   1/1     Running   0          2m42s
tetragon-rthooks-m24xr               1/1     Running   0          2m42s
```

### Test

Start a pod:
```shell
kubectl run test --image=debian  --rm -it -- /bin/bash
```

Check logs:
```shell
minikube ssh 'tail -1 /opt/tetragon/tetragon-oci-hook.log'
```

Output:
```json
{"time":"2024-07-01T10:57:21.435689144Z","level":"INFO","msg":"hook request to agent succeeded","hook":"create-container","start-time":"2024-07-01T10:57:21.433755984Z","req-cgroups":"/kubepods/besteffort/podd4e74de2-0db8-4143-ae55-695b2489c727/crio-828977b42e3149b502b31708778d0c057efbce038af80d0882ed3e0cb0ff8796","req-rootdir":"/run/containers/storage/overlay-containers/828977b42e3149b502b31708778d0c057efbce038af80d0882ed3e0cb0ff8796/userdata","req-containerName":"test"}
```

## Containerd

### Setup Minikube

```shell
minikube start --driver=kvm2 --container-runtime=containerd
minikube image load cilium/tetragon:latest
minikube image load cilium/tetragon-operator:latest
minikube image load cilium/tetragon-rthooks:latest
minikube image ls | grep tetragon
```

Output should be similar to:
```
docker.io/cilium/tetragon:latest
docker.io/cilium/tetragon-rthooks:latest
docker.io/cilium/tetragon-operator:latest
```

Tetragon Runtime Hooks use [NRI](https://github.com/containerd/nri). NRI is [enabled by
default](https://github.com/containerd/containerd/blob/main/docs/NRI.md#disabling-nri-support-in-containerd)
starting from containerd version 2.0. For version 1.7, however, it needs to be enabled in the
configuration.

```shell
minikube ssh cat /etc/containerd/config.toml > /tmp/old-config.toml
./contrib/tetragon-rthooks/tetragon-oci-hook-setup patch-containerd-conf enable-nri --config-file=/tmp/old-config.toml --output=/tmp/new-config.toml
diff -u /tmp/old-config.toml /tmp/new-config.toml
```

Output should be something like:

```diff
--- /tmp/old-config.toml        2024-07-02 11:51:23.893382357 +0200
+++ /tmp/new-config.toml        2024-07-02 11:51:52.841533035 +0200
@@ -67,3 +67,11 @@
     mutation_threshold = 100
     schedule_delay = "0s"
     startup_delay = "100ms"
+  [plugins."io.containerd.nri.v1.nri"]
+    disable = false
+    disable_connections = false
+    plugin_config_path = "/etc/nri/conf.d"
+    plugin_path = "/opt/nri/plugins"
+    plugin_registration_timeout = "5s"
+    plugin_request_timeout = "2s"
+    socket_path = "/var/run/nri/nri.sock"
```

Install the new configuration file and restart containerd
```shell
minikube cp /tmp/new-config.toml /etc/containerd/config.toml
ssh sudo systemctl restart containerd
```

### Install Tetragon

```shell
helm install \
   --namespace kube-system \
   --set tetragon.image.override=docker.io/cilium/tetragon:latest \
   --set tetragonOperator.image.override=docker.io/cilium/tetragon-operator:latest \
   --set rthooks.enabled=true \
   --set rthooks.interface=nri-hook \
   --set rthooks.image.override=docker.io/cilium/tetragon-rthooks:latest \
   tetragon ./install/kubernetes/tetragon
```

```shell
kubectl -n kube-system get pods | grep tetragon
```

Output should be similar to:
```
tetragon-operator-754b85cfd4-2mdd7   1/1     Running   0              24m
tetragon-pjrsf                       2/2     Running   0              24m
tetragon-rthooks-6g8cq               1/1     Running   0              24m
```

### Test

Start a pod:

```shell
kubectl run test --image=debian  --rm -it -- /bin/bash
```

Examine the log file:
```shell
minikube ssh 'tail -1 /opt/tetragon/tetragon-oci-hook.log'
```

Output:
```json
{"time":"2024-07-02T12:02:02.823291054Z","level":"INFO","msg":"hook request to agent succeeded","hook":"createRuntime","start-time":"2024-07-02T12:02:02.816185835Z","req-cgroups":"/kubepods/besteffort/pod9305570c-ac68-4f95-96d8-afbb138bd0b0/42469ae2c52d0ee340b550b8a07a142c9b8cc709aa8ca75b777bb00812149621","req-rootdir":"/run/containerd/io.containerd.runtime.v2.task/k8s.io/42469ae2c52d0ee340b550b8a07a142c9b8cc709aa8ca75b777bb00812149621","req-containerName":"test"}
```
