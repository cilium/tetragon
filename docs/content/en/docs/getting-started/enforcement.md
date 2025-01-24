---
title: "Policy Enforcement"
weight: 6
description: "Enforcing restrictions with Tetragon"
---

Tetragon's tracing policies support monitoring kernel functions to report
events, such as file access events or network connection events, as well as enforcing restrictions on those same kernel functions. Using in-kernel
filtering in Tetragon provides a key performance improvement by limiting events
from kernel to user space. In-kernel filtering
also enables Tetragon to enforce policy restrictions at the kernel level. For
example, by issuing a `SIGKILL` to a process when a policy violation is
detected, the process will not continue to run. If the policy enforcement is
triggered through a syscall this means the application will not return from the
syscall and will be terminated.

In this section, you will add network and file policy enforcement on top of the
Tetragon functionality (execution, file tracing, and network tracing policy)
you've already deployed in this Getting Started guide. Specifically, you will:

* Apply a policy that restricts network traffic egressing a Kubernetes cluster
* Apply a block write and read operations to sensitive files

For specific implementation details refer to the [Enforcement]({{< ref "/docs/concepts/enforcement" >}})
concept section.

## Restricting network traffic on Kubernetes

In this use case you will use a Tetragon tracing policy to block TCP connections
outside the Kubernetes cluster where Tetragon is running. The Tetragon policy is
namespaced, limiting the scope of the enforcement policy to just the "default"
namespace where you installed the demo application in the
[Quick Kubernetes Install]({{< ref "docs/getting-started/install-k8s" >}}) section.

The policy you will use is very similar to the policy you used in the
[Network Monitoring]({{< ref "docs/getting-started/network" >}}) section, but
with enforcement enabled. Although this policy does not use them, Tetragon
tracing policies support including Kubernetes filters, such as namespaces and
labels, so you can limit a policy to targeted namespaces and Pods. This is
critical for effective policy segmentation.

First, ensure you have the proper Pod CIDR captured for use later:

```shell
export PODCIDR=`kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'`
```

You will also need to capture the service CIDR for use in customizing the policy.
When working with managed Kubernetes offerings (AKS, EKS, or GKE) you will need
the environment variables used when you created the cluster.

{{< tabpane lang=shell >}}

{{< tab GKE >}}
export SERVICECIDR=$(gcloud container clusters describe ${NAME} --zone ${ZONE} | awk '/servicesIpv4CidrBlock/ { print $2; }')
{{< /tab >}}

{{< tab Kind >}}
export SERVICECIDR=$(kubectl describe pod -n kube-system kube-apiserver-kind-control-plane | awk -F= '/--service-cluster-ip-range/ {print $2; }')
{{< /tab >}}

{{< tab EKS >}}
export SERVICECIDR=$(aws eks describe-cluster --name ${NAME} | jq -r '.cluster.kubernetesNetworkConfig.serviceIpv4Cidr')
{{< /tab >}}

{{< tab AKS >}}
export SERVICECIDR=$(az aks show --name ${NAME} --resource-group ${AZURE_RESOURCE_GROUP} | jq -r '.networkProfile.serviceCidr)
{{< /tab >}}
{{< /tabpane >}}

When you have captured the Pod CIDR and Service CIDR, then you can customize and
apply the enforcement policy. (If you installed the demo application in a different
namespace than the default namespace, adjust the `kubectl apply` command
accordingly.)

```shell
wget https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/network_egress_cluster_enforce.yaml
envsubst < network_egress_cluster_enforce.yaml | kubectl apply -n default -f -
```

With the enforcement policy applied, run the `tetra getevents` command to observe
events.

{{< tabpane lang=shell >}}
{{< tab "Kubernetes (single node)" >}}
kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --pods xwing
{{< /tab >}}
{{< tab "Kubernetes (multiple nodes)" >}}
POD=$(kubectl -n kube-system get pods -l 'app.kubernetes.io/name=tetragon' -o name --field-selector spec.nodeName=$(kubectl get pod xwing -o jsonpath='{.spec.nodeName}'))
kubectl exec -ti -n kube-system $POD -c tetragon -- tetra getevents -o compact --pods xwing
{{< /tab >}}
{{< /tabpane >}}

To generate an event that Tetragon will report, use `curl` to connect to a
site outside the Kubernetes cluster:

```shell
kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon'
```

The command returns an error code because the egress TCP connects are blocked.
The `tetra` CLI will print the `curl` and annotate that the process that was issued
a `SIGKILL`.

```
command terminated with exit code 137
```

Making network connections to destinations inside the cluster will work as expected:

```shell
kubectl exec -ti xwing -- bash -c 'curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing'
```

The successful internal connection is filtered and will not be shown. The
`tetra getevents` output from the two `curl` commands should look something like
this:

```
🚀 process default/xwing /bin/bash -c "curl https://ebpf.io/applications/#tetragon"
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon
🔌 connect default/xwing /usr/bin/curl tcp 10.32.0.28:45200 -> 104.198.14.52:443
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon SIGKILL
🚀 process default/xwing /bin/bash -c "curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing"
🚀 process default/xwing /usr/bin/curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
```

### Enforce file access restrictions

The following extends the example from [File Access Monitoring]({{< ref "docs/getting-started/file-events" >}})
with enforcement to ensure sensitive files are not read. The policy used is the
[`file_monitoring_enforce.yaml`](https://github.com/cilium/tetragon/blob/main/examples/quickstart/file_monitoring_enforce.yaml),
which you can review and extend as needed. The only difference between the
observation policy and the enforce policy is the addition of an action block
to `SIGKILL` the application and return an error on the operation.

To apply the policy:

{{< tabpane lang=shell >}}

{{< tab "Kubernetes (single node)" >}}
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/file_monitoring.yaml
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/file_monitoring_enforce.yaml
{{< /tab >}}
{{< tab "Kubernetes (multiple nodes)" >}}
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/file_monitoring.yaml
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/file_monitoring_enforce.yaml
{{< /tab >}}
{{< tab Docker >}}
wget https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/file_monitoring_enforce.yaml
docker stop tetragon
docker run --name tetragon --rm --pull always \
  --pid=host --cgroupns=host --privileged               \
  -v ${PWD}/file_monitoring_enforce.yaml:/etc/tetragon/tetragon.tp.d/file_monitoring_enforce.yaml \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf      \
  quay.io/cilium/tetragon:{{< latest-version >}}
{{< /tab >}}
{{< /tabpane >}}

With the policy applied, you can run `tetra getevents` to have Tetragon start
outputting events to the terminal.

{{< tabpane lang=shell >}}
{{< tab "Kubernetes (single node)" >}}
kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --pods xwing
{{< /tab >}}
{{< tab "Kubernetes (multiple nodes)" >}}
POD=$(kubectl -n kube-system get pods -l 'app.kubernetes.io/name=tetragon' -o name --field-selector spec.nodeName=$(kubectl get pod xwing -o jsonpath='{.spec.nodeName}'))
kubectl exec -ti -n kube-system $POD -c tetragon -- tetra getevents -o compact --pods xwing
{{< /tab >}}
{{< tab Docker >}}
docker exec -ti tetragon tetra getevents -o compact
{{< /tab >}}
{{< /tabpane >}}

Next, attempt to read a sensitive file (one of the files included in the defined
policy):

{{< tabpane lang=shell >}}
{{< tab "Kubernetes (single node)" >}}
kubectl exec -ti xwing -- bash -c 'cat /etc/shadow'
{{< /tab >}}
{{< tab "Kubernetes (multiple nodes)" >}}
kubectl exec -ti xwing -- bash -c 'cat /etc/shadow'
{{< /tab >}}
{{< tab Docker >}}
cat /etc/shadow
{{< /tab >}}
{{< /tabpane >}}

Because the file is included in the policy, the command will fail with an error
code.

```shell
kubectl exec -ti xwing -- bash -c 'cat /etc/shadow'
```

The output should be similar to:

```
command terminated with exit code 137
```

This will generate a read event (Docker events will not contain the Kubernetes
metadata shown here).

```
🚀 process default/xwing /bin/bash -c "cat /etc/shadow"
🚀 process default/xwing /bin/cat /etc/shadow
📚 read    default/xwing /bin/cat /etc/shadow
📚 read    default/xwing /bin/cat /etc/shadow
📚 read    default/xwing /bin/cat /etc/shadow
💥 exit    default/xwing /bin/cat /etc/shadow SIGKILL
```

Attempts to read or write to files that are not part of the enforced file policy
are not impacted.

```
🚀 process default/xwing /bin/bash -c "echo foo >> bar; cat bar"
🚀 process default/xwing /bin/cat bar
💥 exit    default/xwing /bin/cat bar 0
💥 exit    default/xwing /bin/bash -c "echo foo >> bar; cat bar" 0
```

## What's next

The completes the Getting Started guide. At this point you should be able to
observe execution traces in a Kubernetes cluster and extend the base deployment
of Tetragon with policies to observe and enforce different aspects of a
Kubernetes system.

The rest of the docs provide further documentation about installation and
using policies. Some useful links:

* To explore details of writing and implementing policies the [Concepts]({{< ref "/docs/concepts" >}})
is a good jumping off point.
* For installation into production environments we recommend reviewing
[Advanced Installations]({{< ref "docs/installation" >}}).
* Finally the [Use Cases]({{< ref "docs/use-cases" >}}) section covers different
uses and deployment concerns related to Tetragon.
