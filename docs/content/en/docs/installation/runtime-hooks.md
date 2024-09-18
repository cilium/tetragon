---
title: "Configure Runtime Hooks"
linkTitle: "Runtime Hooks"
weight: 3
description: "Configure Runtime Hooks"
---

See [Tetragon Runtime Hooks]({{< ref "/docs/concepts/runtime-hooks" >}}), for an introduction to
the topic.


## Install Tetragon with Runtime Hooks

We use `minikube` as the example platform because it supports both `cri-o` and `containerd`, but the
same steps can be applied in other platforms.

### Setup Helm

```shell
helm repo add cilium https://helm.cilium.io
helm repo update
```

### Setup cluster

{{< tabpane text=true >}}

{{% tab "minikube with CRI-O" %}}

```shell
minikube start --driver=kvm2 --container-runtime=cri-o
```
{{% /tab %}}

{{% tab "minikube with Containerd" %}}

```shell
minikube start --driver=kvm2 --container-runtime=cri-o
```

Tetragon Runtime Hooks use [NRI](https://github.com/containerd/nri). NRI is [enabled by
default](https://github.com/containerd/containerd/blob/main/docs/NRI.md#disabling-nri-support-in-containerd)
starting from containerd version 2.0. For version 1.7, however, it needs to be enabled in the
configuration.

This requires a section such as:
```toml
[plugins."io.containerd.nri.v1.nri"]
  disable = false
  disable_connections = false
  plugin_config_path = "/etc/nri/conf.d"
  plugin_path = "/opt/nri/plugins"
  plugin_registration_timeout = "5s"
  plugin_request_timeout = "2s"
  socket_path = "/var/run/nri/nri.sock"
```

To be present in containerd's configuration (e.g., `/etc/containerd/config.toml`).


You can use the `tetragon-oci-hook-setup` to patch the configuration file:
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
minikube ssh sudo systemctl restart containerd
```

{{% /tab %}}

{{< /tabpane >}}

### Install Tetragon

{{< tabpane lang=shell >}}
{{< tab "CRI-O (oci-hooks)" >}}
helm install \
   --namespace kube-system \
   --set rthooks.enabled=true \
   --set rthooks.interface=oci-hooks \
   tetragon ./install/kubernetes/tetragon
{{< /tab >}}
{{< tab "Containerd (nri-hook)" >}}
helm install \
   --namespace kube-system \
   --set rthooks.enabled=true \
   --set rthooks.interface=nri-hook \
   tetragon ./install/kubernetes/tetragon
{{< /tab >}}
{{< /tabpane >}}

```shel
kubecl -n kube-system get pods | grep tetragon
```

With output similar to:
```
tetragon-hpjwq                       2/2     Running   0          2m42s
tetragon-operator-664ddc8957-9lmd2   1/1     Running   0          2m42s
tetragon-rthooks-m24xr               1/1     Running   0          2m42s
```

### Test Runtime hooks

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
