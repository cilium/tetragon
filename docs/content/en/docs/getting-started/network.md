---
title: "Network Monitoring"
weight: 5
description: "Network access traces with Tetragon"
---

This adds a network policy on top of execution and file tracing already
deployed in the quick start. In this case we monitor all network traffic
outside the Kubernetes pod CIDR and service CIDR.

## Kubernetes Cluster Network Access Monitoring

First we must find the pod CIDR and service CIDR in use. The pod
IP CIDR can be found relatively easily in many cases.

```shell-session
export PODCIDR=`kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'`
```

The services CIDR can then be fetched depending on environment. We
require environment variables ZONE and NAME from install steps.

{{< tabpane lang=shell-session >}}

{{< tab GKE >}}
export SERVICECIDR=$(gcloud container clusters describe ${NAME} --zone ${ZONE} | awk '/servicesIpv4CidrBlock/ { print $2; }')
{{< /tab >}}

{{< tab Kind >}}
export SERVICECIDR=$(kubectl describe pod -n kube-system kube-apiserver-kind-control-plane | awk -F= '/--service-cluster-ip-range/ {print $2; }')
{{< /tab >}}

{{< /tabpane >}}

First we apply a policy that includes the `podCIDR` and `serviceIP` list as
filters to avoid filter out cluster local traffic. To apply the policy:

```shell-session
wget https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/network_egress_cluster.yaml
envsubst < network_egress_cluster.yaml | kubectl apply -f -
```

With the file applied we can attach tetra to observe events again:

```shell-session
 kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --pods xwing --processes curl
```

Then execute a curl command in the xwing pod to curl one of our favorite
sites.

```shell-session
 kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon'
```

A connect will be observed in the tetra shell:

```
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon
🔌 connect default/xwing /usr/bin/curl tcp 10.32.0.19:33978 -> 104.198.14.52:443
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon 60
```

We can confirm in-kernel BPF filters are not producing events for in cluster
traffic by issuing a curl to one of our services and noting there is no connect
event.

```shell-session
kubectl exec -ti xwing -- bash -c 'curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing'
```

The output should be similar to:

```
Ship landed
```

And as expected no new events:

```
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon
🔌 connect default/xwing /usr/bin/curl tcp 10.32.0.19:33978 -> 104.198.14.52:443
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon 60
```

## Docker/Baremetal Network Access Monitoring

This example also works easily for local docker users as well except it is not as
obvious to the quickstart authors what IP address CIDR will be useful. The policy
by default will filter all local IPs `127.0.0.1` from the event log. So we can
demo that here.

Set env variables to local loopback IP.
```shell-session
export PODCIDR="127.0.0.1/32"
export SERVICECIDR="127.0.0.1/32"
```

To create the policy,
```shell-session
wget https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/network_egress_cluster.yaml
envsubst < network_egress_cluster.yaml > network_egress_cluster_subst.yaml
```

Start Tetragon with the new policy:
```shell-session
docker stop tetragon-container
docker run --name tetragon-container --rm --pull always \
  --pid=host --cgroupns=host --privileged               \
  -v ${PWD}/network_egress_cluster_subst.yaml:/etc/tetragon/tetragon.tp.d/network_egress_cluster_subst.yaml \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf      \
  quay.io/cilium/tetragon-ci:latest
```

Attach to the tetragon output
```shell-session
docker exec tetragon-container tetra getevents -o compact
```

Now remote TCP connections will be logged and local IPs filters. Executing a curl
to generate a remote TCP connect.
```shell-session
curl https://ebpf.io/applications/#tetragon
```

Produces the following output:
```
🚀 process  /usr/bin/curl https://ebpf.io/applications/#tetragon
🔌 connect  /usr/bin/curl tcp 192.168.1.190:36124 -> 104.198.14.52:443
💥 exit     /usr/bin/curl https://ebpf.io/applications/#tetragon 0
```

# Whats Next

So far we have installed Tetragon and shown a couple policies to monitor
sensitive files and provide network auditing for connections outside our own
cluster and node. Both these cases highlight the value of in kernel filtering.
Another benefit of in-kernel filtering is we can add
[enforcement]({{< ref "/docs/getting-started/enforcement" >}}) to the policies
to not only alert, but block the operation in kernel and/or kill the
application attempting the operation.

To learn more about policies and events Tetragon can implement review the
[Concepts]({{< ref "/docs/concepts" >}}) section.

