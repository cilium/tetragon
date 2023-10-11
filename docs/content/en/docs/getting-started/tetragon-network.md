---
title: "Network Monitoring"
weight: 2
description: "Network Access Traces with Tetragon"
---

This adds a network policy on top of execution and file tracing
already deployed in the quick start. In this case we monitor
all network traffic outside the Kubernetes CIDR.

# Network Access Monitoring

First we apply a policy that includes the podCIDR and serviceIP list as filters
to avoid filter out cluster local traffic. To apply the policy,

{{< tabpane lang=shell-session >}}

{{< tab Kubernetes >}}          
wget http://github.com/cilium/tetragon/quickstart/network_egress_cluster.yaml
kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'| awk '{ for (i = 1; i <= NF; i++) print "        - \"" $i "\"" }' >> network_egress_cluster.yaml
kubectl get services -o jsonpath='{.items[*].spec.clusterIP}'| awk '{ for (i = 1; i <= NF; i++) print "        - \"" $i "\"" }' >> network_egress_cluster.yaml
kubectl apply -f network_egress_cluster.yaml
{{< /tab >}}                                                                                                                                                                   
{{< tab Docker >}}          
{{< /tab >}}                                                                                                                                                                                   
{{< tab Systemd >}}
{{< /tab >}}                                                                                                                                                                                   
{{< /tabpane >}}

With the file applied we can attach tetra to observe events again,

```shell-session
 kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --pods xwing --processes curl
```

Then execute a curl command in the xwing pod to curl one of our favorite
sites.

```shell-session
 kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon'
```

A connect will be observed in the tetra shell

```shell-session
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragonon
🔌 connect default/xwing /usr/bin/curl tcp 10.32.0.19:33978 -> 104.198.14.52:443
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragonon 60
```

We can confirm in-kernel BPF filters are not producing events for in cluster
traffic by issuing a curl to one of our services and noting there is no connect
event.

```shell-session
$ kubectl exec -ti xwing -- bash -c 'curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing'
Ship landed
```

And as expected no new events,

```shell-session
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragonon
🔌 connect default/xwing /usr/bin/curl tcp 10.32.0.19:33978 -> 104.198.14.52:443
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragonon 60
```

# Whats Next
