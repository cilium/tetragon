---
title: "Use case: network observability"
weight: 2
description: "Monitor TCP connect using kprobe hooks"
---

To view TCP connect events, apply the example TCP connect `TracingPolicy`:

```bash
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/tcp-connect.yaml
```

To start monitoring events in the `xwing` pod run the Tetragon CLI:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f | tetra getevents -o compact --namespace default --pod xwing
```

In another terminal, start generate a TCP connection. Here we use
curl.
```bash
kubectl exec -it xwing -- curl http://cilium.io
```
The output in the first terminal will capture the new connect and write,
```bash
🚀 process default/xwing /usr/bin/curl http://cilium.io
🔌 connect default/xwing /usr/bin/curl tcp 10.244.0.6:34965 -> 104.198.14.52:80
📤 sendmsg default/xwing /usr/bin/curl tcp 10.244.0.6:34965 -> 104.198.14.52:80 bytes 73
🧹 close   default/xwing /usr/bin/curl tcp 10.244.0.6:34965 -> 104.198.14.52:80
💥 exit    default/xwing /usr/bin/curl http://cilium.io 0
```

To disable the TracingPolicy run:
```bash
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/tracingpolicy/tcp-connect.yaml
```
