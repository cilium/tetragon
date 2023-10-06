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
as needed. However, files monitored here serve as a good base set of files.

To apply the policy 

{{< tabpane >}}
{{< tab header="K8s" >}}          
kubectl apply -f http://github.com/cilium/tetragon/quickstart/file-monitoring.yaml
{{< /tab >}}                                                                                                                                                                                   
{{< tab header="Docker" >}}          
{{< /tab >}}                                                                                                                                                                                   
{{< tab header="Systemd" >}}
{{< /tab >}}                                                                                                                                                                                   
{{< /tabpane >}}

With the file applied we can attach tetra to observe events again,

```
 kubectl exec -ti -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact --pods xwing
```
Then reading a sensitive file,

```
 kubectl exec -ti xwing -- bash -c 'cat /etc/shadow'
```

This will generate a read event,

```
🚀 process default/xwing /bin/bash -c "cat /etc/shadow"
🚀 process default/xwing /bin/cat /etc/shadow
📚 read    default/xwing /bin/cat /etc/shadow
💥 exit    default/xwing /bin/cat /etc/shadow 0
```

Attempts to write in sensitive directories will similar create an event. For example attempting to write in '/etc'.

```
🚀 process default/xwing /bin/bash -c "echo foo >>  /etc/bar"
📝 write   default/xwing /bin/bash /etc/bar
📝 write   default/xwing /bin/bash /etc/bar
💥 exit    default/xwing /bin/bash -c "echo foo >>  /etc/bar
```

# What's next
