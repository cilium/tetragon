---
title: "File Access Monitoring"
weight: 2
description: "File Access Traces with Tetragon"
---

Tracing Policies can be added to Tetragon through YAML configuration files
that extend Tetragon's base execution tracing capabilities. These policies
do filtering in kernel to ensure only interesting events are published
to userspace from the BPF programs running in kernel. This ensures overhead
remains low even on busy systems.

# File Access Monitoring

The following extends the example from Execution Tracing with a policy to
monitor sensitive files in Linux. The policy used is the [`file-monitoring.yaml`](https://github.com/cilium/tetragon/blob/main/quickstart/file-monitoring.yaml) it can be reviewed and extended
as needed. Files monitored here serve as a good base set of files.

To apply the policy Kubernetes uses a CRD that can be applied with kubectl.
Uses the same YAML configuration as Kuberenetes, but loaded through a file
on disk.

{{< tabpane lang=shell-session >}}

{{< tab Kubernetes >}}          
kubectl apply -f http://github.com/cilium/tetragon/quickstart/file-monitoring.yaml
{{< /tab >}}                                                                                                                                                                                   
{{< tab Docker >}}          
wget http://github.com/cilium/tetragon/quickstart/file-monitoring.yaml
docker stop tetragon-container
docker run --name tetragon-container --rm --pull always \
  --pid=host --cgroupns=host --privileged               \
  -v ${PWD}/file_monitoring.yaml:/etc/tetragon/tetragon.tp.d/file_monitoring.yaml \
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

This will generate a read event (Docker events will omit Kubernetes metadata),

```shell-session
🚀 process default/xwing /bin/bash -c "cat /etc/shadow"
🚀 process default/xwing /bin/cat /etc/shadow
📚 read    default/xwing /bin/cat /etc/shadow
💥 exit    default/xwing /bin/cat /etc/shadow 0
```

Attempts to write in sensitive directories will similar create an event. For example attempting to write in '/etc'.

```shell-session
🚀 process default/xwing /bin/bash -c "echo foo >>  /etc/bar"
📝 write   default/xwing /bin/bash /etc/bar
📝 write   default/xwing /bin/bash /etc/bar
💥 exit    default/xwing /bin/bash -c "echo foo >>  /etc/bar
```

# What's next

To explore tracing policies for networking try the [Networking Monitoring]({{< ref "/docs/getting-started/network" >}}) quickstart.
To dive into the details of policies and events please see [Concepts]({{< ref "docs/concepts" >}}) section.
