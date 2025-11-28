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
same steps can be applied to other platforms.

### Setup cluster

{{< tabpane text=true >}}

{{% tab "minikube with CRI-O" %}}

```shell
minikube start --driver=kvm2 --container-runtime=cri-o
```
{{% /tab %}}

{{% tab "minikube with Containerd" %}}

```shell
minikube start --driver=kvm2 --container-runtime=containerd
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

You can use the `minikube-install-hook` script to patch the configuration file:
```shell
./contrib/tetragon-rthooks/scripts/minikube-install-hook.sh --nri
```

This script updates the configuration and restarts containerd.

{{% /tab %}}

{{% tab "kind (with Containerd)" %}}

Note: Kind [only supports
containerd](https://kind.sigs.k8s.io/docs/design/principles/#target-cri-functionality)
currently.

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

Tetragon Runtime Hooks use [NRI](https://github.com/containerd/nri). NRI is [enabled by
default](https://github.com/containerd/containerd/blob/main/docs/NRI.md#disabling-nri-support-in-containerd)
starting from containerd version 2.0. For version 1.7, however, it needs to be enabled in the
configuration.

You can check the containerd version using:

```shell
docker exec -it kind-control-plane crictl version
```

Output should be similar to:

```
Version:  0.1.0
RuntimeName:  containerd
RuntimeVersion:  v1.7.18
RuntimeApiVersion:  v1
```

Assuming that the containerd version is earlier than 2.0,
you can use the `tetragon-oci-hook-setup` to patch the configuration file:

```shell
docker cp kind-control-plane:/etc/containerd/config.toml /tmp/old-config.toml
./contrib/tetragon-rthooks/tetragon-oci-hook-setup patch-containerd-conf enable-nri --config-file=/tmp/old-config.toml --output=/tmp/new-config.toml
diff -u /tmp/old-config.toml /tmp/new-config.toml
```

Output should be something like:

```diff
--- /tmp/old-config.toml        2024-08-13 23:31:06.000000000 +0200
+++ /tmp/new-config.toml        2025-04-30 10:42:28.707064377 +0200
@@ -40,3 +40,11 @@
   tolerate_missing_hugepages_controller = true
      # restrict_oom_score_adj needs to be true when running inside UserNS (rootless)
         restrict_oom_score_adj = false
         +[plugins."io.containerd.nri.v1.nri"]
         +  disable = false
         +  disable_connections = false
         +  plugin_config_path = "/etc/nri/conf.d"
         +  plugin_path = "/opt/nri/plugins"
         +  plugin_registration_timeout = "5s"
         +  plugin_request_timeout = "2s"
         +  socket_path = "/var/run/nri/nri.sock"
```

Install the new configuration file and restart containerd

```shell
docker cp /tmp/new-config.toml kind-control-plane:/etc/containerd/config.toml
docker exec -it kind-control-plane systemctl restart containerd
```

{{% /tab %}}

{{< /tabpane >}}

### Install Tetragon

```shell
helm repo add cilium https://helm.cilium.io
helm repo update
```

{{< tabpane lang=shell >}}
{{< tab "CRI-O (oci-hooks)" >}}
helm install \
   --namespace kube-system \
   --set rthooks.enabled=true \
   --set rthooks.interface=oci-hooks \
   ${EXTRA_HELM_FLAGS[@]} \
   tetragon cilium/tetragon
{{< /tab >}}
{{< tab "Containerd (nri-hook)" >}}
helm install \
   --namespace kube-system \
   --set rthooks.enabled=true \
   --set rthooks.interface=nri-hook \
   ${EXTRA_HELM_FLAGS[@]} \
   tetragon cilium/tetragon
{{< /tab >}}
{{< /tabpane >}}

```shell
kubectl -n kube-system get pods | grep tetragon
```

With output similar to:
```
tetragon-hpjwq                       2/2     Running   0          2m42s
tetragon-operator-664ddc8957-9lmd2   1/1     Running   0          2m42s
tetragon-rthooks-m24xr               1/1     Running   0          2m42s
```

### Test Runtime Hooks

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

## Configuring Runtime Hooks installation

### Installation directory (`installDir`)

For tetragon runtime hooks to work, a binary (`tetragon-oci-hook`) needs to be installed on the
host. Installation happens by the `tetragon-rthooks` daemonset and the binary is installed in
`/opt/tetragon` by default.

In some systems, however, the `/opt` directory is mounted read-only. This will result in
errors such as:

```
Warning  FailedMount  8s (x5 over 15s)  kubelet            MountVolume.SetUp failed for volume "oci-hook-install-path" : mkdir /opt/tetragon: read-only file system                                                                                                                                     (6 results) [48/6775]
```

You can use the `rthooks.installDir` helm variable to select a different location. For example:

```
--set rthooks.installDir=/run/tetragon
```


### Failure check (`failAllowNamespaces`)

By default, `tetragon-oci-hook` logs information to `/opt/tetragon/tetragon-oci-hook.log`.
Inspecting this file we get the following messages.

```json
{"time":"2024-03-05T15:18:52.669044463Z","level":"WARN","msg":"hook request to the agent failed","hook":"create-container","start-time":"2024-03-05T15:18:42.667916779Z","req-cgroups":"/kubepods/besteffort/pod43ec7f32-3c9f-429f-a01c-fbaafff9f8e1/crio-1d18fd58f0879f6152a1c421f8f1e0987845394ee17001a16bee2df441c112f3","req-rootdir":"/run/containers/storage/overlay-containers/1d18fd58f0879f6152a1c421f8f1e0987845394ee17001a16bee2df441c112f3/userdata","err":"connecting to agent (context deadline exceeded) failed: unix:///var/run/cilium/tetragon/tetragon.sock"}
{"time":"2024-03-05T15:18:52.66912411Z","level":"INFO","msg":"failCheck determined that we should not fail this container, even if there was an error","hook":"create-container","start-time":"2024-03-05T15:18:42.667916779Z"}
{"time":"2024-03-05T15:18:53.01093915Z","level":"WARN","msg":"hook request to the agent failed","hook":"create-container","start-time":"2024-03-05T15:18:43.01005032Z","req-cgroups":"/kubepods/burstable/pod60f971e6-ac38-4aa0-b2d3-549333b2c803/crio-c0bf4e38bfa4ed5c58dd314d505f8b6a0f513d2f2de4dc4aa86a55c7c3e963ab","req-rootdir":"/run/containers/storage/overlay-containers/c0bf4e38bfa4ed5c58dd314d505f8b6a0f513d2f2de4dc4aa86a55c7c3e963ab/userdata","err":"connecting to agent (context deadline exceeded) failed: unix:///var/run/cilium/tetragon/tetragon.sock"}
{"time":"2024-03-05T15:18:53.010999098Z","level":"INFO","msg":"failCheck determined that we should not fail this container, even if there was an error","hook":"create-container","start-time":"2024-03-05T15:18:43.01005032Z"}
{"time":"2024-03-05T15:19:04.034580703Z","level":"WARN","msg":"hook request to the agent failed","hook":"create-container","start-time":"2024-03-05T15:18:54.033449685Z","req-cgroups":"/kubepods/besteffort/pod43ec7f32-3c9f-429f-a01c-fbaafff9f8e1/crio-d95e61f118557afdf3713362b9034231fee9bd7033fc8e7cc17d1efccac6f54f","req-rootdir":"/run/containers/storage/overlay-containers/d95e61f118557afdf3713362b9034231fee9bd7033fc8e7cc17d1efccac6f54f/userdata","err":"connecting to agent (context deadline exceeded) failed: unix:///var/run/cilium/tetragon/tetragon.sock"}
{"time":"2024-03-05T15:19:04.03463995Z","level":"INFO","msg":"failCheck determined that we should not fail this container, even if there was an error","hook":"create-container","start-time":"2024-03-05T15:18:54.033449685Z"}
```

To understand these messages, consider what `tetragon-oci-hook` should do if it
cannot contact the Tetragon agent.

You may want to stop certain workloads from running. For other workloads (for example, the
tetragon pod itself) you probably want to do the opposite and let the them start. To this end,
`tetragon-oci-hook` checks the container annotations, and by default does not fail a container if it
belongs in the same namespace as Tetragon. The previous messages concern the tetragon containers
(`tetragon-operator` and `tetragon`) and they indicate that the choice was made not to fail this
container from starting.

Furthermore, users may specify additional namespaces where the container will not fail if the
tetragon agent cannot be contacted via the `rthooks.failAllowNamespaces` option.

For example:
```yaml
rthooks:
  enabled: true
  failAllowNamespaces: namespace1,namespace2
```
