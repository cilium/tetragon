---
title: "Network Monitoring"
weight: 5
description: "Network access traces with Tetragon"
---

In addition to file access monitoring, Tetragon's tracing policies also support
monitoring network access. In this section, you will see how to monitor network
traffic to "external" destinations (destinations that are outside the
Kubernetes cluster or external to the Docker host where Tetragon is running).
These instructions assume you already have Tetragon running in either
Kubernetes or Docker, and that you have deployed the Cilium demo application.

## Monitoring Kubernetes network access

First, you'll need to find the pod CIDR and service CIDR in use. In many cases
the pod CIDR is relatively easy to find.

```shell
export PODCIDR=`kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'`
```

You can fetch the service CIDR from the cluster in some environments. When
working with managed Kubernetes offerings (AKS, EKS, or GKE) you will need the
environment variables used when you created the cluster.

{{< tabpane lang=shell >}}

{{< tab GKE >}}
export SERVICECIDR=$(gcloud container clusters describe ${NAME} --zone ${ZONE} | awk '/servicesIpv4CidrBlock/ { print $2; }')
{{< /tab >}}

{{< tab Kind >}}
export SERVICECIDR=$(kubectl describe pod -n kube-system -l component=kube-apiserver | awk -F= '/--service-cluster-ip-range/ {print $2; }')
{{< /tab >}}

{{< tab EKS >}}
export SERVICECIDR=$(aws eks describe-cluster --name ${NAME} | jq -r '.cluster.kubernetesNetworkConfig.serviceIpv4Cidr')
{{< /tab >}}

{{< tab AKS >}}
export SERVICECIDR=$(az aks show --name ${NAME} --resource-group ${AZURE_RESOURCE_GROUP} | jq -r '.networkProfile.serviceCidr)
{{< /tab >}}
{{< /tabpane >}}

Once you have this information, you can customize a policy to exclude network
traffic to the networks stored in the `PODCIDR` and `SERVICECIDR` environment
variables. Use `envsubst` to do this, and then apply the policy to your
Kubernetes cluster with `kubectl apply`:

```shell
wget https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/network_egress_cluster.yaml
envsubst < network_egress_cluster.yaml | kubectl apply -f -
```

Once the tracing policy is applied, you can attach `tetra` to observe events
again:

{{< tabpane lang=shell >}}

{{< tab "Kubernetes (single node)" >}}
kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --pods xwing --processes curl
{{< /tab >}}

{{< tab "Kubernetes (multiple nodes" >}}
POD=$(kubectl -n kube-system get pods -l 'app.kubernetes.io/name=tetragon' -o name --field-selector spec.nodeName=$(kubectl get pod xwing -o jsonpath='{.spec.nodeName}'))
kubectl exec -ti -n kube-system $POD -c tetragon -- tetra getevents -o compact --pods xwing --processes curl
{{< /tab >}}
{{< /tabpane >}}

Then execute a `curl` command in the "xwing" Pod to access one of our favorite
sites.

```shell
 kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon'
```

You will observe a `connect` event being reported in the output of the `tetra getevents` command:

```
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon
🔌 connect default/xwing /usr/bin/curl tcp 10.32.0.19:33978 -> 104.198.14.52:443
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon 60
```

You can confirm in-kernel BPF filters are not producing events for in-cluster
traffic by issuing a `curl` to one of our services and noting there is no
`connect` event.

```shell
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

## Monitoring Docker or bare metal network access

This example also works easily for local Docker users. However, since Docker
does not have pod CIDR or service CIDR constructs, you will construct a tracing
policy that filters `127.0.0.1` from the Tetragon event log.

First, set the necessary environment variables to the loopback IP address.

```shell
export PODCIDR="127.0.0.1/32"
export SERVICECIDR="127.0.0.1/32"
```

Next, customize the policy using `envsubst`.

```shell
wget https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/network_egress_cluster.yaml
envsubst < network_egress_cluster.yaml > network_egress_cluster_subst.yaml
```

Finally, start Tetragon with the new policy.

```shell
docker stop tetragon
docker run -d --name tetragon --rm --pull always \
  --pid=host --cgroupns=host --privileged               \
  -v ${PWD}/network_egress_cluster_subst.yaml:/etc/tetragon/tetragon.tp.d/network_egress_cluster_subst.yaml \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf      \
  quay.io/cilium/tetragon:{{< latest-version >}}
```

Once Tetragon is running, use `docker exec` to run the `tetra getevents` command
and log the output to your terminal.

```shell
docker exec -ti tetragon tetra getevents -o compact
```

Now remote TCP connections will be logged, but connections to the localhost
address are filtered out by Tetragon. You can see this by executing a `curl`
command to generate a remote TCP connect.

```shell
curl https://ebpf.io/applications/#tetragon
```

This produces the following output:

```
🚀 process  /usr/bin/curl https://ebpf.io/applications/#tetragon
🔌 connect  /usr/bin/curl tcp 192.168.1.190:36124 -> 104.198.14.52:443
💥 exit     /usr/bin/curl https://ebpf.io/applications/#tetragon 0
```

## What's next

So far you have installed Tetragon and used a couple policies to monitor
sensitive files and provide network auditing for connections outside your own
cluster and node. Both these cases highlight the value of in-kernel filtering.
Another benefit of in-kernel filtering is you can add
[enforcement]({{< ref "/docs/getting-started/enforcement" >}}) to the policies
to not only alert via a log entry, but to block the operation in kernel and/or
kill the application attempting the operation.

To learn more about policies and events Tetragon can implement review the
[Concepts]({{< ref "/docs/concepts" >}}) section.
