---
title: "Policy Enforcement"
weight: 6
description: "Policy Enforcement"
---

This adds a network and file policy enforcement on top of execution, file tracing
and networking policy already deployed in the quick start.  In this use case we use
a namespace filter to limit the scope of the enforcement policy to just the `darkstar`
cluster we installed the demo application in from the
[Quick Kubernetes Install]({{< ref "docs/getting-started/install-k8s" >}}).

This highlights two important concepts of Tetragon. First in kernel filtering
provides a key performance improvement by limiting events from kernel to user
space. But, also allows for enforcing policies in the kernel. By issueing a
`SIGKILL` to the process at this point the application will be stopped from
continuing to run. If the operation is triggered through a syscall this means
the application will not return from the syscall and will be terminated.

Second, by including kubernetes filters, such as namespace and labels we can
segment a policy to apply to targeted namespaces and pods. This is critical
for effective policy segmentation.

For implementation details see the [Enforcement]({{< ref "/docs/concepts/enforcement" >}})
concept section.

## Kubernetes Enforcement

The following section is layed out with the following:
- A guide to promote the network observation policy that observer all network
  traffic egressing the cluster to enforce this policy.
- A guide to promote the file access monitoring policy to block write and read
  operations to sensitive files.

### Block TCP Connect outside Cluster

First we will deploy the [Network Monitoring]({{< ref "docs/getting-started/network" >}})
policy with enforcement on. For this case the policy is written to only apply
against the `empire` namespace. This limits the scope of the policy for the
getting started guide.

Ensure we have the proper Pod CIDRs

```shell-session
export PODCIDR=`kubectl get nodes -o jsonpath='{.items[*].spec.podCIDR}'`
```

 and Service CIDRs configured.

{{< tabpane lang=shell-session >}}
{{< tab GKE >}}
export SERVICECIDR=$(gcloud container clusters describe ${NAME} --zone ${ZONE} --project ${PROJECT} | awk '/servicesIpv4CidrBlock/ { print $2; }')
{{< /tab >}}

{{< tab Kind >}}
export SERVICECIDR=$(kubectl describe pod -n kube-system kube-apiserver-kind-control-plane | awk -F= '/--service-cluster-ip-range/ {print $2; }')
{{< /tab >}}
{{< /tabpane >}}

Then we can apply the egress cluster enforcement policy

```shell-session
wget https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/network_egress_cluster_enforce.yaml
envsubst < network_egress_cluster_enforce.yaml | kubectl apply -n default -f -
```

With the enforcement policy applied we can attach tetra to observe events again:

```shell-session
kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --pods xwing
```

And once again execute a curl command in the xwing:

```shell-session
kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon'
```

The command returns an error code because the egress TCP connects are blocked shown here.
```
command terminated with exit code 137
```

Connect inside the cluster will work as expected,

```shell-session
kubectl exec -ti xwing -- bash -c 'curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing'
```

The Tetra CLI will print the curl and annotate that the process that was issued
a Sigkill. The successful internal connect is filtered and will not be shown.

```
🚀 process default/xwing /bin/bash -c "curl https://ebpf.io/applications/#tetragon"
🚀 process default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon
🔌 connect default/xwing /usr/bin/curl tcp 10.32.0.28:45200 -> 104.198.14.52:443
💥 exit    default/xwing /usr/bin/curl https://ebpf.io/applications/#tetragon SIGKILL
🚀 process default/xwing /bin/bash -c "curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing"
🚀 process default/xwing /usr/bin/curl -s -XPOST deathstar.default.svc.cluster.local/v1/request-landing
```

### Enforce File Access Monitoring

The following extends the example from [File Access Monitoring]({{< ref "docs/getting-started/file-events" >}})
with enforcement to ensure sensitive files are not read. The policy used is the
[`file_monitoring_enforce.yaml`](https://github.com/cilium/tetragon/blob/main/examples/quickstart/file_monitoring_enforce.yaml)
it can be reviewed and extended as needed. The only difference between the
observation policy and the enforce policy is the addition of an action block
to sigkill the application and return an error on the op.

To apply the policy:

{{< tabpane lang=shell-session >}}

{{< tab Kubernetes >}}
kubectl delete -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/file_monitoring.yaml
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/file_monitoring_enforce.yaml
{{< /tab >}}
{{< tab Docker >}}
wget https://raw.githubusercontent.com/cilium/tetragon/main/examples/quickstart/file_monitoring.yaml
docker stop tetragon-container
docker run --name tetragon-container --rm --pull always \
  --pid=host --cgroupns=host --privileged               \
  -v ${PWD}/file_monitoring.yaml:/etc/tetragon/tetragon.tp.d/file_monitoring_enforce.yaml \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf      \
  quay.io/cilium/tetragon-ci:latest
{{< /tab >}}
{{< /tabpane >}}

With the file applied we can attach tetra to observe events again,

{{< tabpane lang=shell-session >}}
{{< tab Kubernetes >}}
kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --pods xwing
{{< /tab >}}
{{< tab Docker >}}
docker exec tetragon-container tetra getevents -o compact
{{< /tab >}}
{{< /tabpane >}}

Then reading a sensitive file,

{{< tabpane lang=shell-session >}}
{{< tab Kubernetes >}}
kubectl exec -ti xwing -- bash -c 'cat /etc/shadow'
{{< /tab >}}
{{< tab Docker >}}
cat /etc/shadow
{{< /tab >}}
{{< /tabpane >}}

The command will fail with an error code because this is one of our sensitive files,
```shell-session
kubectl exec -ti xwing -- bash -c 'cat /etc/shadow'
```

The output should be similar to:

```
command terminated with exit code 137
```

This will generate a read event (Docker events will omit Kubernetes metadata),

```
🚀 process default/xwing /bin/bash -c "cat /etc/shadow"
🚀 process default/xwing /bin/cat /etc/shadow
📚 read    default/xwing /bin/cat /etc/shadow
📚 read    default/xwing /bin/cat /etc/shadow
📚 read    default/xwing /bin/cat /etc/shadow
💥 exit    default/xwing /bin/cat /etc/shadow SIGKILL
```

Writes and reads to files not part of the enforced file policy will not be
impacted.

```
🚀 process default/xwing /bin/bash -c "echo foo >> bar; cat bar"
🚀 process default/xwing /bin/cat bar
💥 exit    default/xwing /bin/cat bar 0
💥 exit    default/xwing /bin/bash -c "echo foo >> bar; cat bar" 0
```

## What's next

The completes the quick start guides. At this point we should be able to
observe execution traces in a Kubernetes cluster and extend the base deployment
of Tetragon with policies to observe and enforce different aspects of a
Kubernetes system.

The rest of the docs provide further documentation about installation and
using policies. Some useful links:

To explore details of writing and implementing policies the [Concepts]({{< ref "/docs/concepts" >}}) is a good jumping off point.
For installation into production environments we recommend reviewing [Advanced Installations]({{< ref "docs/installation" >}}).
For a more in depth discussion on Tetragon overhead and how we measure system load try [Benchmarks]({{< ref "docs/benchmarks" >}}).
Finally [Use Cases]({{< ref "docs/use-cases" >}}) and [Tutorials]({{< ref "docs/tutorials" >}}) cover different uses and deployment concerns related to Tetragon.
