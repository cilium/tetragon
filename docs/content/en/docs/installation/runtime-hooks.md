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
locally:

```shell-session
$ make image image-operator image-rthooks # build images within a tetragon checked out git repo
```

## CRI-O

### Setup Minikube

```shell-session
$ minikube start --driver=kvm2 --container-runtime=cri-o
$ minikube image load cilium/tetragon:latest
$ minikube image load cilium/tetragon-operator:latest
$ minikube image load cilium/tetragon-rthooks:latest
$ minikube image ls | grep tetragon
localhost/cilium/tetragon:latest
localhost/cilium/tetragon-rthooks:latest
localhost/cilium/tetragon-operator:latest
```
### Install Tetragon

```shell-session
$ helm install \
   --namespace kube-system \
   --set tetragon.image.override=localhost/cilium/tetragon:latest \
   --set tetragonOperator.image.override=localhost/cilium/tetragon-operator:latest \
   --set rthooks.enabled=true \
   --set rthooks.interface=oci-hooks \
   --set rthooks.image.override=localhost/cilium/tetragon-rthooks:latest \
   tetragon ./install/kubernetes/tetragon
```


```shell-session
$ kubectl -n kube-system get pods | grep tetragon
tetragon-hpjwq                       2/2     Running   0          2m42s
tetragon-operator-664ddc8957-9lmd2   1/1     Running   0          2m42s
tetragon-rthooks-m24xr               1/1     Running   0          2m42s
```

### Test

Start a pod:
```shell-session
$ kubectl run test --image=debian  --rm -it -- /bin/bash
```

Check logs:
```shell-session
$ minikube ssh 'tail -1 /opt/tetragon/tetragon-oci-hook.log'
{"time":"2024-07-01T10:57:21.435689144Z","level":"INFO","msg":"hook request to agent succeeded","hook":"create-container","start-time":"2024-07-01T10:57:21.433755984Z","req-cgroups":"/kubepods/besteffort/podd4e74de2-0db8-4143-ae55-695b2489c727/crio-828977b42e3149b502b31708778d0c057efbce038af80d0882ed3e0cb0ff8796","req-rootdir":"/run/containers/storage/overlay-containers/828977b42e3149b502b31708778d0c057efbce038af80d0882ed3e0cb0ff8796/userdata","req-containerName":"test"}
```
