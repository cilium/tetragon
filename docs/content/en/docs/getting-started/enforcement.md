---
title: "Policy Enforcement"
weight: 2
description: "Policy Enforcement"
---

This adds a network and file policy enforcement on top of execution, file tracing
and networking policy already deployed in the quick start. In this use case we
use a namespace and pod labels to limit the scope of where the network, file
and some security policies will be applied. This highlights two important concepts
of Tetragon. First in kernel filter provides performance advantages, but also allows for
enforcing policies inline with the action. Second, by including kubernetes
filters, such as namespace and labels we can segment a policy to apply to
targeted pods. For implementation details see Enforcement section and for
modifying and creating additional policies see Tracing Policies.

# Enforcement

To apply the policy 

{{< tabpane >}}
{{< tab header="K8s" >}}          
kubectl apply -f tbd.base-enforce.yaml
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

The CLI will print the exec tracing and file access as before, but will additional show the network connection outside the K8s cluster.

#
