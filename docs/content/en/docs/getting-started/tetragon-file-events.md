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

The following extens the example from Execution Tracing with a policy to
monitor sensitive files in Linux. This will monitor the directory '/etc'
and the following files known,

```
filef
foo
bar
```

To apply the policy 

{{< tabpane >}}
{{< tab header="K8s" >}}          
kubectl apply -f tbd.yaml
{{< /tab >}}                                                                                                                                                                                   
{{< tab header="Docker" >}}          
{{< /tab >}}                                                                                                                                                                                   
{{< tab header="Systemd" >}}
{{< /tab >}}                                                                                                                                                                                   
{{< /tabpane >}}

With the file applied we can attach tetra to observe events again,

```
 kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon
```

And once again execute a curl command in the xwing,

```
 kubectl exec -ti xwing -- bash -c 'curl https://ebpf.io/applications/#tetragon
```

The CLI will print the exec tracing as before, but will additional show sensitive file accesses
needed by curl to access SSH keys.

# What's next
